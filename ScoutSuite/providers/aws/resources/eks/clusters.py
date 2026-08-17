from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id

# The control plane log types a cluster may emit, none of which is on by default
LOGGING_TYPES = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']


class Clusters(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        raw_clusters = await self.facade.eks.get_clusters(self.region)
        for raw_cluster in raw_clusters:
            name, resource = self._parse_cluster(raw_cluster)
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
        cluster['cluster_sg_group'] = raw_cluster['cluster']['resourcesVpcConfig']['clusterSecurityGroupId']
        cluster['cluster_vpc'] = raw_cluster['cluster']['resourcesVpcConfig']['vpcId']
        cluster['region'] = self.region

        self._parse_logging(raw_cluster['cluster'], cluster)

        return get_non_provider_id(cluster['name']), cluster

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