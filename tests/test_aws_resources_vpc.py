import unittest

from ScoutSuite.providers.aws.resources.vpc.route_tables import RouteTables
from ScoutSuite.providers.aws.resources.vpc.subnets import Subnets


class Facade:
    partition = 'aws'


LOCAL_ROUTE = {'DestinationCidrBlock': '10.0.0.0/16', 'GatewayId': 'local',
               'Origin': 'CreateRouteTable', 'State': 'active'}


def parse_route_table(routes, associations=None, **attributes):
    raw_route_table = {'RouteTableId': 'rtb-01234567890123456',
                       'VpcId': 'vpc-01234567890123456',
                       'OwnerId': '123456789012',
                       'Routes': routes,
                       'Associations': associations if associations is not None else []}
    raw_route_table.update(attributes)
    return RouteTables(Facade(), 'eu-west-1', 'vpc-01234567890123456')._parse_route_table(raw_route_table)[1]


def parse_subnet(route_table):
    raw_subnet = {'SubnetId': 'subnet-01234567890123456',
                  'SubnetArn': 'arn:aws:ec2:eu-west-1:123456789012:subnet/subnet-01234567890123456',
                  'VpcId': 'vpc-01234567890123456',
                  'Ipv6CidrBlockAssociationSet': [],
                  'route_table': route_table}
    return Subnets(Facade(), 'eu-west-1', 'vpc-01234567890123456')._parse_subnet(raw_subnet)[1]


class TestAWSRouteTableRoutes(unittest.TestCase):

    def test_route_targets_are_flattened(self):
        route_table = parse_route_table([
            LOCAL_ROUTE,
            {'DestinationCidrBlock': '0.0.0.0/0', 'NatGatewayId': 'nat-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'},
            {'DestinationIpv6CidrBlock': '::/0', 'EgressOnlyInternetGatewayId': 'eigw-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'},
            {'DestinationPrefixListId': 'pl-01234567890123456', 'GatewayId': 'vpce-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'}])

        assert route_table['routes_count'] == 4
        assert [route['target_type'] for route in route_table['routes']] == \
            ['local', 'nat_gateway', 'egress_only_internet_gateway', 'vpc_endpoint']
        assert [route['destination_type'] for route in route_table['routes']] == \
            ['ipv4', 'ipv4', 'ipv6', 'prefix_list']
        assert route_table['routes'][2]['destination'] == '::/0'
        assert route_table['routes'][3]['destination'] == 'pl-01234567890123456'

    def test_gateway_targets_are_told_apart_by_prefix(self):
        route_table = parse_route_table([
            LOCAL_ROUTE,
            {'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'},
            {'DestinationCidrBlock': '10.1.0.0/16', 'GatewayId': 'vgw-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'}])

        assert [route['target_type'] for route in route_table['routes']] == \
            ['local', 'internet_gateway', 'virtual_private_gateway']

    def test_blackhole_routes(self):
        route_table = parse_route_table([
            LOCAL_ROUTE,
            {'DestinationCidrBlock': '172.16.0.0/16', 'VpcPeeringConnectionId': 'pcx-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'blackhole'}])

        assert route_table['blackhole_routes'] == ['172.16.0.0/16']

    def test_no_blackhole_route(self):
        assert parse_route_table([LOCAL_ROUTE])['blackhole_routes'] == []


class TestAWSRouteTablePublicness(unittest.TestCase):

    def test_default_route_to_internet_gateway(self):
        route_table = parse_route_table([
            LOCAL_ROUTE,
            {'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'}])

        assert route_table['is_public'] is True

    def test_narrow_route_to_internet_gateway_is_not_a_public_subnet(self):
        # Reaching a handful of external addresses through the gateway does not put the subnet on the
        # public path, nothing being routed back to it from the rest of the Internet
        route_table = parse_route_table([
            LOCAL_ROUTE,
            {'DestinationCidrBlock': '203.0.113.0/24', 'GatewayId': 'igw-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'}])

        assert route_table['is_public'] is False

    def test_blackhole_route_to_internet_gateway_is_not_a_public_subnet(self):
        route_table = parse_route_table([
            LOCAL_ROUTE,
            {'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'blackhole'}])

        assert route_table['is_public'] is False

    def test_egress_only_gateway_is_not_a_public_subnet(self):
        route_table = parse_route_table([
            LOCAL_ROUTE,
            {'DestinationIpv6CidrBlock': '::/0', 'EgressOnlyInternetGatewayId': 'eigw-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'}])

        assert route_table['is_public'] is False

    def test_nat_gateway_is_not_a_public_subnet(self):
        route_table = parse_route_table([
            LOCAL_ROUTE,
            {'DestinationCidrBlock': '0.0.0.0/0', 'NatGatewayId': 'nat-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'}])

        assert route_table['is_public'] is False


class TestAWSRouteTablePeeringRoutes(unittest.TestCase):

    def test_route_within_the_peer_cidr_block(self):
        route_table = parse_route_table([
            LOCAL_ROUTE,
            {'DestinationCidrBlock': '172.16.0.0/16', 'VpcPeeringConnectionId': 'pcx-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'}])

        assert route_table['permissive_peering_routes'] == []

    def test_route_broader_than_any_vpc(self):
        route_table = parse_route_table([
            LOCAL_ROUTE,
            {'DestinationCidrBlock': '10.0.0.0/8', 'VpcPeeringConnectionId': 'pcx-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'}])

        assert route_table['permissive_peering_routes'] == ['10.0.0.0/8']

    def test_default_route_to_a_peering_connection(self):
        route_table = parse_route_table([
            LOCAL_ROUTE,
            {'DestinationCidrBlock': '0.0.0.0/0', 'VpcPeeringConnectionId': 'pcx-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'},
            {'DestinationIpv6CidrBlock': '::/0', 'VpcPeeringConnectionId': 'pcx-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'}])

        assert route_table['permissive_peering_routes'] == ['0.0.0.0/0', '::/0']

    def test_broad_route_to_something_other_than_a_peering_connection(self):
        # A transit gateway route is expected to be broad, aggregation being what a transit gateway
        # is for, and CIS 4.4 is about peering connections
        route_table = parse_route_table([
            LOCAL_ROUTE,
            {'DestinationCidrBlock': '10.0.0.0/8', 'TransitGatewayId': 'tgw-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'}])

        assert route_table['permissive_peering_routes'] == []

    def test_prefix_list_route_to_a_peering_connection(self):
        # The prefix list content is not part of the route, so its breadth cannot be judged here
        route_table = parse_route_table([
            LOCAL_ROUTE,
            {'DestinationPrefixListId': 'pl-01234567890123456',
             'VpcPeeringConnectionId': 'pcx-01234567890123456',
             'Origin': 'CreateRoute', 'State': 'active'}])

        assert route_table['permissive_peering_routes'] == []


class TestAWSRouteTableAssociations(unittest.TestCase):

    def test_main_route_table(self):
        route_table = parse_route_table(
            [LOCAL_ROUTE],
            [{'Main': True, 'RouteTableAssociationId': 'rtbassoc-01234567890123456',
              'AssociationState': {'State': 'associated'}}])

        assert route_table['main'] is True
        assert route_table['subnets'] == []
        # The main table governs every subnet not associated with another one, so it is always in use
        assert route_table['used'] is True

    def test_subnet_associations(self):
        route_table = parse_route_table(
            [LOCAL_ROUTE],
            [{'Main': False, 'SubnetId': 'subnet-01234567890123456'},
             {'Main': False, 'SubnetId': 'subnet-11234567890123456'}])

        assert route_table['subnets'] == ['subnet-01234567890123456', 'subnet-11234567890123456']
        assert route_table['associations_count'] == 2
        assert route_table['used'] is True

    def test_gateway_association(self):
        route_table = parse_route_table(
            [LOCAL_ROUTE], [{'Main': False, 'GatewayId': 'vgw-01234567890123456'}])

        assert route_table['gateways'] == ['vgw-01234567890123456']
        assert route_table['used'] is True

    def test_unused_route_table(self):
        route_table = parse_route_table([LOCAL_ROUTE], [])

        assert route_table['main'] is False
        assert route_table['associations_count'] == 0
        assert route_table['used'] is False

    def test_propagating_virtual_private_gateways(self):
        route_table = parse_route_table(
            [LOCAL_ROUTE], [], PropagatingVgws=[{'GatewayId': 'vgw-01234567890123456'}])

        assert route_table['propagating_vgws'] == ['vgw-01234567890123456']


class TestAWSSubnetPublicness(unittest.TestCase):

    def test_subnet_governed_by_a_public_route_table(self):
        subnet = parse_subnet({'RouteTableId': 'rtb-01234567890123456',
                               'Routes': [LOCAL_ROUTE,
                                          {'DestinationCidrBlock': '0.0.0.0/0',
                                           'GatewayId': 'igw-01234567890123456',
                                           'Origin': 'CreateRoute', 'State': 'active'}]})

        assert subnet['is_public'] is True
        assert subnet['route_table_id'] == 'rtb-01234567890123456'
        # The route table itself is not carried over, it is a resource of its own
        assert 'route_table' not in subnet

    def test_subnet_governed_by_a_private_route_table(self):
        subnet = parse_subnet({'RouteTableId': 'rtb-01234567890123456',
                               'Routes': [LOCAL_ROUTE,
                                          {'DestinationCidrBlock': '0.0.0.0/0',
                                           'NatGatewayId': 'nat-01234567890123456',
                                           'Origin': 'CreateRoute', 'State': 'active'}]})

        assert subnet['is_public'] is False
        assert subnet['route_table_id'] == 'rtb-01234567890123456'

    def test_subnet_with_no_route_table_resolved(self):
        subnet = parse_subnet(None)

        assert subnet['is_public'] is False
        assert subnet['route_table_id'] is None


if __name__ == '__main__':
    unittest.main()
