from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Nodegroups(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for cluster_name in await self.facade.eks.get_cluster_names(self.region):
            raw_nodegroups = await self.facade.eks.get_nodegroups(self.region, cluster_name)
            if not raw_nodegroups:
                continue

            # Only worth describing the cluster once there is a nodegroup to compare it against
            cluster = await self.facade.eks.get_cluster(self.region, cluster_name)
            for raw_nodegroup in raw_nodegroups:
                name, resource = self._parse_nodegroup(raw_nodegroup, cluster_name, cluster.get('version'))
                self[name] = resource

    def _parse_nodegroup(self, raw_nodegroup, cluster_name, cluster_version):
        scaling_config = raw_nodegroup.get('scalingConfig', {})
        resources = raw_nodegroup.get('resources', {})
        instance_types = raw_nodegroup.get('instanceTypes', [])
        created_at = raw_nodegroup.get('createdAt')
        modified_at = raw_nodegroup.get('modifiedAt')

        node = {}
        node['name'] = raw_nodegroup['nodegroupName']
        node['nodegroupArn'] = raw_nodegroup.get('nodegroupArn')
        node['clusterName'] = raw_nodegroup.get('clusterName', cluster_name)
        node['Nodegroup_version'] = raw_nodegroup.get('version')
        node['MinSize'] = scaling_config.get('minSize')
        node['MaxSize'] = scaling_config.get('maxSize')
        node['desiredSize'] = scaling_config.get('desiredSize')
        node['Node_sg'] = resources.get('remoteAccessSecurityGroup')
        node['created_at'] = created_at.strftime('%Y-%m-%d %H:%M:%S') if created_at else None
        node['modified_at'] = modified_at.strftime('%Y-%m-%d %H:%M:%S') if modified_at else None
        node['status'] = raw_nodegroup.get('status')
        node['capacityType'] = raw_nodegroup.get('capacityType')
        node['region'] = self.region
        node['instanceTypes'] = instance_types[0] if instance_types else None
        node['amiType'] = raw_nodegroup.get('amiType')
        node['diskSize'] = raw_nodegroup.get('diskSize')
        node['nodeRole'] = raw_nodegroup.get('nodeRole')

        # EKS refuses to run a nodegroup ahead of its control plane, so any difference here means
        # the nodegroup is the one lagging behind
        node['cluster_version'] = cluster_version
        node['version_behind_cluster'] = \
            bool(cluster_version) and node['Nodegroup_version'] != cluster_version

        # Nodegroup names are only unique within a cluster:
        return get_non_provider_id(f"{node['clusterName']}/{node['name']}"), node
