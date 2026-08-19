from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.utils import get_name

from .route_tables import is_internet_facing, parse_route


class Subnets(AWSResources):
    def __init__(self, facade: AWSFacade, region: str, vpc: str):
        self.region = region
        self.vpc = vpc

        super().__init__(facade)

    async def fetch_all(self):
        raw_subnets = await self.facade.ec2.get_subnets(self.region, self.vpc)
        for raw_subnet in raw_subnets:
            id, subnet = self._parse_subnet(raw_subnet)
            self[id] = subnet

    def _parse_subnet(self, raw_subnet):
        raw_subnet['id'] = raw_subnet['SubnetId']
        get_name(raw_subnet, raw_subnet, 'SubnetId')
        raw_subnet.pop('SubnetId')
        raw_subnet['arn'] = raw_subnet.pop('SubnetArn')

        self._set_routing(raw_subnet)

        if raw_subnet['Ipv6CidrBlockAssociationSet']:
            raw_subnet['CidrBlockv6'] = raw_subnet['Ipv6CidrBlockAssociationSet'][0]['Ipv6CidrBlock']
        else:
            raw_subnet['CidrBlockv6'] = None

        return raw_subnet['id'], raw_subnet

    @staticmethod
    def _set_routing(raw_subnet):
        """A subnet is public when the route table that governs it sends unmatched traffic to an
        internet gateway. Nothing on the subnet itself says so: MapPublicIpOnLaunch only decides
        whether instances get an address, not whether that address is reachable."""

        route_table = raw_subnet.pop('route_table', None)

        raw_subnet['route_table_id'] = route_table.get('RouteTableId') if route_table else None
        raw_subnet['is_public'] = bool(route_table) and is_internet_facing(
            [parse_route(raw_route) for raw_route in route_table.get('Routes', [])])
