from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources


class DaxClusters(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super(DaxClusters, self).__init__(facade)
        self.region = region

    async def fetch_all(self):
        raw_clusters = await self.facade.dynamodb.get_dax_clusters(self.region)
        for raw_cluster in raw_clusters:
            name, resource = self._parse_cluster(raw_cluster)
            self[name] = resource

    def _parse_cluster(self, raw_cluster):
        cluster_dict = {}
        cluster_dict['id'] = cluster_dict['name'] = raw_cluster.get('ClusterName')
        cluster_dict['arn'] = raw_cluster.get('ClusterArn')
        cluster_dict['description'] = raw_cluster.get('Description')
        cluster_dict['status'] = raw_cluster.get('Status')
        cluster_dict['node_type'] = raw_cluster.get('NodeType')
        cluster_dict['total_nodes'] = raw_cluster.get('TotalNodes')
        cluster_dict['active_nodes'] = raw_cluster.get('ActiveNodes')
        cluster_dict['nodes'] = raw_cluster.get('Nodes')
        cluster_dict['subnet_group'] = raw_cluster.get('SubnetGroup')
        cluster_dict['security_groups'] = raw_cluster.get('SecurityGroups')
        cluster_dict['parameter_group'] = raw_cluster.get('ParameterGroup')
        cluster_dict['iam_role_arn'] = raw_cluster.get('IamRoleArn')
        cluster_dict['cluster_discovery_endpoint'] = raw_cluster.get('ClusterDiscoveryEndpoint')
        cluster_dict['tags'] = raw_cluster.get('tags')

        # Encryption at rest, only ever reported when it was turned on at creation time
        cluster_dict['sse_status'] = raw_cluster.get('SSEDescription', {}).get('Status')
        cluster_dict['sse_enabled'] = cluster_dict['sse_status'] in ['ENABLING', 'ENABLED']

        # Encryption in transit, NONE or TLS, also fixed at creation time
        encryption_type = raw_cluster.get('ClusterEndpointEncryptionType')
        cluster_dict['endpoint_encryption_type'] = encryption_type
        cluster_dict['encryption_in_transit_enabled'] = encryption_type == 'TLS'

        return cluster_dict['id'], cluster_dict
