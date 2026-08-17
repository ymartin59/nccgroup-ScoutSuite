from typing import Dict, List

from ScoutSuite.core.console import print_exception
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently, map_concurrently


class EKSFacade(AWSBaseFacade):

    async def get_cluster_names(self, region: str) -> List[str]:
        try:
            return await AWSFacadeUtils.get_all_pages(
                'eks', region, self.session, 'list_clusters', 'clusters')
        except Exception as e:
            print_exception(f'Failed to list EKS clusters: {e}')
            return []

    async def get_clusters(self, region: str):
        cluster_names = await self.get_cluster_names(region)
        if not cluster_names:
            return []

        clusters = await map_concurrently(
            self._get_cluster, cluster_names, region=region)

        return [cluster for cluster in clusters if cluster]

    async def get_cluster(self, region: str, cluster_name: str) -> Dict:
        raw_cluster = await self._get_cluster(cluster_name, region)
        return raw_cluster.get('cluster', {})

    async def get_nodegroups(self, region: str, cluster_name: str):
        try:
            nodegroup_names = await AWSFacadeUtils.get_all_pages(
                'eks', region, self.session, 'list_nodegroups', 'nodegroups', clusterName=cluster_name)
        except Exception as e:
            print_exception(f'Failed to list EKS nodegroups of cluster {cluster_name}: {e}')
            return []

        if not nodegroup_names:
            return []

        nodegroups = await map_concurrently(
            self._get_nodegroup, nodegroup_names, region=region, cluster_name=cluster_name)

        return [nodegroup for nodegroup in nodegroups if nodegroup]

    async def _get_cluster(self, cluster_name: str, region: str) -> Dict:
        eks_client = AWSFacadeUtils.get_client('eks', self.session, region)
        try:
            return await run_concurrently(
                lambda: eks_client.describe_cluster(name=cluster_name))
        except Exception as e:
            print_exception(f'Failed to describe EKS cluster {cluster_name}: {e}')
            return {}

    async def _get_nodegroup(self, node_name: str, region: str, cluster_name: str) -> Dict:
        eks_client = AWSFacadeUtils.get_client('eks', self.session, region)
        try:
            return await run_concurrently(
                lambda: eks_client.describe_nodegroup(
                    clusterName=cluster_name, nodegroupName=node_name)['nodegroup'])
        except Exception as e:
            print_exception(f'Failed to describe EKS nodegroup {node_name} of cluster {cluster_name}: {e}')
            return {}
