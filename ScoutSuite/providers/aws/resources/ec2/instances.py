from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.utils import get_name, get_keys, format_arn, identify_user_data_secrets


class EC2Instances(AWSResources):
    def __init__(self, facade: AWSFacade, region: str, vpc: str):
        super().__init__(facade)
        self.region = region
        self.vpc = vpc
        self.partition = facade.partition
        self.service = 'ec2'
        self.resource_type = 'instance'

    async def fetch_all(self):
        raw_instances = await self.facade.ec2.get_instances(self.region, self.vpc)
        for raw_instance in raw_instances:
            name, resource = await self._parse_instance(raw_instance)
            self[name] = resource

    async def _parse_instance(self, raw_instance):
        instance = {}
        id = raw_instance['InstanceId']
        instance['id'] = id
        instance['arn'] = format_arn(self.partition, self.service, self.region, raw_instance['OwnerId'], raw_instance['InstanceId'], self.resource_type)
        instance['reservation_id'] = raw_instance['ReservationId']
        instance['availability_zone'] = raw_instance.get('Placement', {}).get('AvailabilityZone')
        instance['monitoring_enabled'] = raw_instance['Monitoring']['State'] == 'enabled'
        instance['user_data'] = await self.facade.ec2.get_instance_user_data(self.region, id)
        instance['user_data_secrets'] = self._identify_user_data_secrets(instance['user_data'])

        get_name(raw_instance, instance, 'InstanceId')
        get_keys(raw_instance, instance,
                 ['KeyName', 'LaunchTime', 'InstanceType', 'State', 'IamInstanceProfile', 'SubnetId', 'Tags'])

        if "IamInstanceProfile" in raw_instance:
            instance['iam_instance_profile_id'] = raw_instance['IamInstanceProfile']['Id']
            instance['iam_instance_profile_arn'] = raw_instance['IamInstanceProfile']['Arn']
        
        instance['network_interfaces'] = {}
        for eni in raw_instance['NetworkInterfaces']:
            nic = {}
            get_keys(eni, nic, ['Association', 'Groups', 'PrivateIpAddresses', 'SubnetId', 'Ipv6Addresses'])
            instance['network_interfaces'][eni['NetworkInterfaceId']] = nic

        instance['metadata_options'] = raw_instance.get('MetadataOptions', {})

        if 'IamInstanceProfile' in raw_instance:
            instance['iam_role'] = raw_instance['IamInstanceProfile']['Arn'].split('/')[-1]
        else:
            instance['iam_role'] = None

        return id, instance

    @staticmethod
    def _identify_user_data_secrets(user_data):
        """
        Parses EC2 user data in order to identify secrets and credentials..
        """
        return identify_user_data_secrets(user_data)
