from ScoutSuite.providers.aws.resources.vpcs import Vpcs

from .network_acls import NetworkACLs
from .route_tables import RouteTables
from .subnets import Subnets


class RegionalVpcs(Vpcs):
    _children = [
        (NetworkACLs, 'network_acls'),
        (RouteTables, 'route_tables'),
        (Subnets, 'subnets'),
    ]
