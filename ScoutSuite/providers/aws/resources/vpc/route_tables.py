import netaddr

from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.utils import get_name, format_arn

DEFAULT_IPV4_DESTINATION = '0.0.0.0/0'
DEFAULT_IPV6_DESTINATION = '::/0'

# A VPC CIDR block can be no larger than a /16, so a route to a peering connection broader than that
# necessarily covers addresses the peer does not own.
LARGEST_VPC_PREFIX_LENGTH = 16

# The route attribute naming the target, in the order AWS documents them. A route has exactly one.
ROUTE_TARGET_ATTRIBUTES = [
    ('GatewayId', 'gateway'),
    ('NatGatewayId', 'nat_gateway'),
    ('TransitGatewayId', 'transit_gateway'),
    ('VpcPeeringConnectionId', 'peering_connection'),
    ('EgressOnlyInternetGatewayId', 'egress_only_internet_gateway'),
    ('CarrierGatewayId', 'carrier_gateway'),
    ('LocalGatewayId', 'local_gateway'),
    ('NetworkInterfaceId', 'network_interface'),
    ('InstanceId', 'instance'),
    ('CoreNetworkArn', 'core_network')
]

# What a GatewayId can point at, told apart by its prefix
GATEWAY_TYPE_PREFIXES = [
    ('igw-', 'internet_gateway'),
    ('vgw-', 'virtual_private_gateway'),
    ('vpce-', 'vpc_endpoint'),
    ('eigw-', 'egress_only_internet_gateway')
]


def parse_route(raw_route: dict):
    """Flatten a route into a destination, a target and the type of each, the API spreading all three
    over a dozen mutually exclusive attributes."""

    route = {}

    if raw_route.get('DestinationCidrBlock'):
        route['destination'] = raw_route['DestinationCidrBlock']
        route['destination_type'] = 'ipv4'
    elif raw_route.get('DestinationIpv6CidrBlock'):
        route['destination'] = raw_route['DestinationIpv6CidrBlock']
        route['destination_type'] = 'ipv6'
    else:
        route['destination'] = raw_route.get('DestinationPrefixListId')
        route['destination_type'] = 'prefix_list'

    route['target'] = route['target_type'] = None
    for attribute, target_type in ROUTE_TARGET_ATTRIBUTES:
        if raw_route.get(attribute):
            route['target'] = raw_route[attribute]
            route['target_type'] = target_type
            break

    if route['target_type'] == 'gateway':
        route['target_type'] = _gateway_type(route['target'])

    route['state'] = raw_route.get('State')
    route['origin'] = raw_route.get('Origin')

    return route


def _gateway_type(gateway_id: str):
    # A route to the VPC's own CIDR block carries the literal string 'local' as its gateway
    if gateway_id == 'local':
        return 'local'
    for prefix, gateway_type in GATEWAY_TYPE_PREFIXES:
        if gateway_id.startswith(prefix):
            return gateway_type
    return 'gateway'


def is_internet_facing(routes: list):
    """Whether the route table sends unmatched traffic to an internet gateway, which is what makes
    every subnet it governs a public subnet. An egress-only gateway does not count: it carries
    outbound IPv6 traffic and refuses connections opened from outside."""

    return any(route['target_type'] == 'internet_gateway'
               and route['destination'] in (DEFAULT_IPV4_DESTINATION, DEFAULT_IPV6_DESTINATION)
               and route['state'] == 'active'
               for route in routes)


def _is_broader_than_a_vpc(destination: str, destination_type: str):
    if destination_type not in ('ipv4', 'ipv6'):
        return False
    if destination in (DEFAULT_IPV4_DESTINATION, DEFAULT_IPV6_DESTINATION):
        return True
    try:
        return netaddr.IPNetwork(destination).prefixlen < LARGEST_VPC_PREFIX_LENGTH
    except netaddr.AddrFormatError:
        return False


class RouteTables(AWSResources):
    def __init__(self, facade: AWSFacade, region: str, vpc: str):
        super().__init__(facade)
        self.region = region
        self.vpc = vpc
        self.partition = facade.partition
        self.service = 'ec2'
        self.resource_type = 'route-table'

    async def fetch_all(self):
        raw_route_tables = await self.facade.ec2.get_route_tables(self.region, self.vpc)
        for raw_route_table in raw_route_tables:
            id, route_table = self._parse_route_table(raw_route_table)
            self[id] = route_table

    def _parse_route_table(self, raw_route_table):
        route_table = {}
        route_table['id'] = raw_route_table.get('RouteTableId')
        route_table['name'] = get_name(raw_route_table, raw_route_table, 'RouteTableId')
        route_table['arn'] = format_arn(self.partition, self.service, self.region,
                                        raw_route_table.get('OwnerId'), route_table['id'],
                                        self.resource_type)
        route_table['vpc_id'] = raw_route_table.get('VpcId')
        route_table['owner_id'] = raw_route_table.get('OwnerId')
        route_table['tags'] = raw_route_table.get('Tags')

        route_table['routes'] = [parse_route(raw_route) for raw_route in raw_route_table.get('Routes', [])]
        route_table['routes_count'] = len(route_table['routes'])

        associations = raw_route_table.get('Associations', [])
        route_table['main'] = any(association.get('Main') for association in associations)
        route_table['subnets'] = [association['SubnetId'] for association in associations
                                  if association.get('SubnetId')]
        route_table['gateways'] = [association['GatewayId'] for association in associations
                                   if association.get('GatewayId')]
        # The main table governs every subnet that is not explicitly associated with another one, so
        # it is in use whether or not it carries an association of its own
        route_table['associations_count'] = len(route_table['subnets']) + len(route_table['gateways'])
        route_table['used'] = route_table['main'] or route_table['associations_count'] > 0

        route_table['propagating_vgws'] = [vgw['GatewayId'] for vgw
                                           in raw_route_table.get('PropagatingVgws', [])]

        route_table['is_public'] = is_internet_facing(route_table['routes'])

        # A route whose target no longer exists. Traffic to the destination is dropped, and if the
        # target is ever recreated with the same identifier the route silently comes back to life.
        route_table['blackhole_routes'] = [route['destination'] for route in route_table['routes']
                                           if route['state'] == 'blackhole']

        # CIS asks that routes to a peered VPC be least-access; anything broader than a /16 reaches
        # past the peer's own address space
        route_table['permissive_peering_routes'] = \
            [route['destination'] for route in route_table['routes']
             if route['target_type'] == 'peering_connection'
             and _is_broader_than_a_vpc(route['destination'], route['destination_type'])]

        return route_table['id'], route_table
