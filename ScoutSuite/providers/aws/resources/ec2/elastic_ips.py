from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.utils import get_name, format_arn


class ElasticIPs(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region
        self.partition = facade.partition
        self.service = 'ec2'
        self.resource_type = 'elastic-ip'

    async def fetch_all(self):
        raw_elastic_ips = await self.facade.ec2.get_elastic_ips(self.region)
        for raw_elastic_ip in raw_elastic_ips:
            id, elastic_ip = self._parse_elastic_ip(raw_elastic_ip)
            self[id] = elastic_ip

    def _parse_elastic_ip(self, raw_elastic_ip):
        elastic_ip = {}
        # An address allocated for use in a VPC is identified by its allocation id; an EC2-Classic one
        # has none and is identified by the address itself
        elastic_ip['id'] = raw_elastic_ip.get('AllocationId') or raw_elastic_ip.get('PublicIp')
        elastic_ip['allocation_id'] = raw_elastic_ip.get('AllocationId')
        elastic_ip['name'] = get_name(raw_elastic_ip, raw_elastic_ip, 'PublicIp')
        elastic_ip['arn'] = format_arn(self.partition, self.service, self.region,
                                       self.facade.owner_id, elastic_ip['id'], self.resource_type)
        elastic_ip['public_ip'] = raw_elastic_ip.get('PublicIp')
        elastic_ip['domain'] = raw_elastic_ip.get('Domain')
        elastic_ip['public_ipv4_pool'] = raw_elastic_ip.get('PublicIpv4Pool')
        elastic_ip['network_border_group'] = raw_elastic_ip.get('NetworkBorderGroup')
        elastic_ip['carrier_ip'] = raw_elastic_ip.get('CarrierIp')
        elastic_ip['customer_owned_ip'] = raw_elastic_ip.get('CustomerOwnedIp')
        elastic_ip['tags'] = raw_elastic_ip.get('Tags')

        # The other half of the mapping a public address needs to be attributed: which interface, and
        # therefore which instance and which private address, answers on it
        elastic_ip['association_id'] = raw_elastic_ip.get('AssociationId')
        elastic_ip['instance_id'] = raw_elastic_ip.get('InstanceId') or None
        elastic_ip['network_interface_id'] = raw_elastic_ip.get('NetworkInterfaceId')
        elastic_ip['network_interface_owner_id'] = raw_elastic_ip.get('NetworkInterfaceOwnerId')
        elastic_ip['private_ip_address'] = raw_elastic_ip.get('PrivateIpAddress')
        elastic_ip['subnet_id'] = raw_elastic_ip.get('SubnetId')

        elastic_ip['associated'] = bool(elastic_ip['instance_id']
                                       or elastic_ip['network_interface_id'])

        # An address AWS manages on behalf of a service, a NAT gateway for instance. It is attached
        # to something even when nothing in the account owns the attachment.
        elastic_ip['service_managed'] = raw_elastic_ip.get('ServiceManaged')

        return elastic_ip['id'], elastic_ip
