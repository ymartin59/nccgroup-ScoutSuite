import datetime

from ScoutSuite.core.console import print_exception
from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id

# The control plane log types a cluster may emit, none of which is on by default
LOGGING_TYPES = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']

# The EKS API does not report whether the Kubernetes version of a cluster is still supported, so the
# release calendar has to be transcribed here and updated from time to time.
# https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html
END_OF_STANDARD_SUPPORT_LAST_UPDATED = datetime.date(2026, 8, 17)

# Table of Kubernetes version : end of standard support. A version below the oldest entry went out of
# support long before it, and a version above the newest one is assumed to still be supported.
END_OF_STANDARD_SUPPORT = {
    '1.21': datetime.date(2023, 2, 15),
    '1.22': datetime.date(2023, 6, 4),
    '1.23': datetime.date(2023, 10, 11),
    '1.24': datetime.date(2024, 1, 31),
    '1.25': datetime.date(2024, 5, 1),
    '1.26': datetime.date(2024, 6, 11),
    '1.27': datetime.date(2024, 7, 24),
    '1.28': datetime.date(2024, 11, 26),
    '1.29': datetime.date(2025, 3, 23),
    '1.30': datetime.date(2025, 7, 23),
    '1.31': datetime.date(2025, 11, 26),
    '1.32': datetime.date(2026, 3, 23),
    '1.33': datetime.date(2026, 7, 31),
}


class Clusters(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region
        self._version_table_warning_shown = False

    async def fetch_all(self):
        raw_clusters = await self.facade.eks.get_clusters(self.region)
        if not raw_clusters:
            return

        oidc_provider_urls = await self.facade.eks.get_iam_oidc_provider_urls()
        for raw_cluster in raw_clusters:
            name, resource = self._parse_cluster(raw_cluster)
            await self._parse_service_account_iam_roles(raw_cluster['cluster'], resource, oidc_provider_urls)
            self[name] = resource

    def _parse_cluster(self, raw_cluster):
        cluster = {}
        cluster['name'] = raw_cluster['cluster']['name']
        cluster['status'] = raw_cluster['cluster']['status']
        cluster['arn'] = raw_cluster['cluster']['arn']
        cluster['created_at'] = raw_cluster['cluster']['createdAt'].strftime('%Y-%m-%d %H:%M:%S')
        cluster['endpoint'] = raw_cluster['cluster']['endpoint']
        cluster['role_arn'] = raw_cluster['cluster']['roleArn']
        cluster['version'] = raw_cluster['cluster']['version']
        cluster['endpointPublicAccess'] = raw_cluster['cluster']['resourcesVpcConfig']['endpointPublicAccess']
        cluster['endpointPrivateAccess'] = raw_cluster['cluster']['resourcesVpcConfig']['endpointPrivateAccess']
        # Only meaningful while public access is enabled, and left at its 0.0.0.0/0 default otherwise
        cluster['public_access_cidrs'] = \
            raw_cluster['cluster']['resourcesVpcConfig'].get('publicAccessCidrs', [])
        cluster['cluster_sg_group'] = raw_cluster['cluster']['resourcesVpcConfig']['clusterSecurityGroupId']
        cluster['cluster_vpc'] = raw_cluster['cluster']['resourcesVpcConfig']['vpcId']
        cluster['region'] = self.region

        self._parse_logging(raw_cluster['cluster'], cluster)
        self._parse_encryption(raw_cluster['cluster'], cluster)
        self._parse_access_config(raw_cluster['cluster'], cluster)
        self._parse_version_support(raw_cluster['cluster'], cluster)

        return get_non_provider_id(cluster['name']), cluster

    def _parse_version_support(self, raw_cluster, cluster):
        # A cluster left past the end of standard support is either being patched under extended
        # support, at a cost, or waiting to be upgraded by AWS on its own schedule
        cluster['upgrade_support_type'] = (raw_cluster.get('upgradePolicy') or {}).get('supportType')

        end_of_support = END_OF_STANDARD_SUPPORT.get(cluster['version'])
        cluster['version_end_of_standard_support'] = str(end_of_support) if end_of_support else None

        if end_of_support:
            cluster['version_unsupported'] = datetime.date.today() >= end_of_support
        else:
            minor = self._get_minor_version(cluster['version'])
            oldest_tracked = min(self._get_minor_version(v) for v in END_OF_STANDARD_SUPPORT)
            cluster['version_unsupported'] = minor is not None and minor < oldest_tracked

        self._warn_if_version_table_is_stale()

    @staticmethod
    def _get_minor_version(version):
        try:
            return int(str(version).split('.')[1])
        except (IndexError, ValueError):
            return None

    def _warn_if_version_table_is_stale(self):
        if self._version_table_warning_shown:
            return

        age = datetime.date.today() - END_OF_STANDARD_SUPPORT_LAST_UPDATED
        if age > datetime.timedelta(days=180):
            print_exception('The EKS end of standard support table has not been updated in over 180 '
                            'days. Please update ScoutSuite to the latest release or update the table '
                            'in ScoutSuite/providers/aws/resources/eks/clusters.py')
            self._version_table_warning_shown = True

    @staticmethod
    def _parse_access_config(raw_cluster, cluster):
        # Clusters created before access entries existed report no access configuration at all, and
        # the aws-auth ConfigMap is then the only thing that maps IAM principals to the cluster
        access_config = raw_cluster.get('accessConfig') or {}
        cluster['authentication_mode'] = access_config.get('authenticationMode', 'CONFIG_MAP')
        cluster['bootstrap_cluster_creator_admin_permissions'] = \
            access_config.get('bootstrapClusterCreatorAdminPermissions')

    async def _parse_service_account_iam_roles(self, raw_cluster, cluster, oidc_provider_urls):
        # Every cluster is handed an OIDC issuer URL, but IAM roles for service accounts only work
        # once that URL is registered as an IAM identity provider of the account. EKS pod identity
        # is the other way to give a pod its own role, and needs no identity provider at all.
        issuer = raw_cluster.get('identity', {}).get('oidc', {}).get('issuer')
        cluster['oidc_issuer'] = issuer
        cluster['oidc_provider_registered'] = \
            bool(issuer) and issuer.split('://', 1)[-1] in oidc_provider_urls

        associations = await self.facade.eks.get_pod_identity_associations(self.region, cluster['name'])
        cluster['pod_identity_associations_count'] = len(associations)

    @staticmethod
    def _parse_encryption(raw_cluster, cluster):
        # 'secrets' is the only resource EKS encrypts with a customer key, and the key can be set on
        # an existing cluster but never changed or removed afterwards
        key_arns = [
            config['provider']['keyArn']
            for config in raw_cluster.get('encryptionConfig') or []
            if 'secrets' in config.get('resources', []) and config.get('provider', {}).get('keyArn')
        ]

        cluster['secrets_kms_key'] = key_arns[0] if key_arns else None
        cluster['secrets_encrypted_with_kms'] = bool(key_arns)

    @staticmethod
    def _parse_logging(raw_cluster, cluster):
        # describe_cluster groups the log types by whether they are enabled, so an entry of
        # clusterLogging carries a list of types and the single flag that applies to all of them.
        # Reading one entry, or one type per entry, therefore misses most of the configuration.
        enabled_types = []
        for log_setup in raw_cluster.get('logging', {}).get('clusterLogging', []):
            if log_setup.get('enabled'):
                enabled_types += log_setup.get('types', [])

        cluster['logging_enabled_types'] = enabled_types
        cluster['logging_disabled_types'] = [t for t in LOGGING_TYPES if t not in enabled_types]
        # Whether the cluster sends anything at all to CloudWatch Logs
        cluster['logging'] = bool(enabled_types)
        for log_type in LOGGING_TYPES:
            cluster[f'type_logging_{log_type}'] = log_type in enabled_types