import json

from ScoutSuite.core.console import print_exception
from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.utils import format_arn, get_name


class VpcEndpoints(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region
        self.partition = facade.partition
        self.service = 'ec2'
        self.resource_type = 'vpc-endpoint'

    async def fetch_all(self):
        raw_vpc_endpoints = await self.facade.ec2.get_vpc_endpoints(self.region)

        for raw_vpc_endpoint in raw_vpc_endpoints:
            id, vpc_endpoint = self._parse_vpc_endpoint(raw_vpc_endpoint)
            self[id] = vpc_endpoint

    def _parse_vpc_endpoint(self, raw_vpc_endpoint):
        vpc_endpoint = {}
        vpc_endpoint['id'] = raw_vpc_endpoint.get('VpcEndpointId')
        vpc_endpoint['arn'] = format_arn(self.partition, self.service, self.region, '',
                                         vpc_endpoint['id'], self.resource_type)
        get_name(raw_vpc_endpoint, vpc_endpoint, 'VpcEndpointId')
        vpc_endpoint['vpc_id'] = raw_vpc_endpoint.get('VpcId')
        vpc_endpoint['service_name'] = raw_vpc_endpoint.get('ServiceName')
        vpc_endpoint['type'] = raw_vpc_endpoint.get('VpcEndpointType')
        vpc_endpoint['state'] = raw_vpc_endpoint.get('State')
        vpc_endpoint['creation_timestamp'] = raw_vpc_endpoint.get('CreationTimestamp')
        vpc_endpoint['route_table_ids'] = raw_vpc_endpoint.get('RouteTableIds')
        vpc_endpoint['subnet_ids'] = raw_vpc_endpoint.get('SubnetIds')
        vpc_endpoint['security_groups'] = raw_vpc_endpoint.get('Groups')
        vpc_endpoint['private_dns_enabled'] = raw_vpc_endpoint.get('PrivateDnsEnabled')
        vpc_endpoint['dns_entries'] = raw_vpc_endpoint.get('DnsEntries')
        vpc_endpoint['tags'] = raw_vpc_endpoint.get('Tags')

        # The endpoint policy is returned as a JSON string, and is absent from interface endpoints
        # created without one
        raw_policy = raw_vpc_endpoint.get('PolicyDocument')
        if raw_policy:
            try:
                vpc_endpoint['policy'] = json.loads(raw_policy)
            except ValueError as e:
                print_exception('Failed to parse the policy of VPC endpoint {}: {}'.format(vpc_endpoint['id'], e))

        return vpc_endpoint['id'], vpc_endpoint
