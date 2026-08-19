import asyncio
import boto3

from ScoutSuite.core.console import print_exception, print_warning
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.utils import decode_user_data
from ScoutSuite.providers.utils import get_and_set_concurrently
from ScoutSuite.providers.utils import run_concurrently


class EC2Facade(AWSBaseFacade):
    regional_flow_logs_cache_locks = {}
    flow_logs_cache = {}
    regional_route_tables_cache_locks = {}
    route_tables_cache = {}

    def __init__(self, session: boto3.session.Session, owner_id: str):
        self.owner_id = owner_id

        super().__init__(session)

    async def get_instance_user_data(self, region: str, instance_id: str):
        ec2_client = AWSFacadeUtils.get_client('ec2', self.session, region)
        try:
            user_data_response = await run_concurrently(
                lambda: ec2_client.describe_instance_attribute(Attribute='userData', InstanceId=instance_id))
        except Exception as e:
            print_exception(
                f'Failed to describe EC2 instance attributes: {e}')
            return None
        else:
            if 'Value' not in user_data_response['UserData'].keys():
                return None
            else:
                try:
                    return await self._decode_user_data(user_data_response['UserData']['Value'])
                except Exception as e:
                    print_exception(f'Unable to decode EC2 instance user data: {e}')

    async def _decode_user_data(self, user_data):
        return decode_user_data(user_data)

    async def get_instances(self, region: str, vpc: str):
        filters = [{'Name': 'vpc-id', 'Values': [vpc]}]
        try:
            reservations = \
                await AWSFacadeUtils.get_all_pages(
                    'ec2', region, self.session, 'describe_instances', 'Reservations', Filters=filters)

            instances = []
            for reservation in reservations:
                for instance in reservation['Instances']:
                    instance['ReservationId'] = reservation['ReservationId']
                    instance['OwnerId'] = reservation['OwnerId']
                    instances.append(instance)

            return instances
        except Exception as e:
            print_exception(f'Failed to describe EC2 instances: {e}')
            return []

    async def get_security_groups(self, region: str, vpc: str):
        filters = [{'Name': 'vpc-id', 'Values': [vpc]}]
        try:
            return await AWSFacadeUtils.get_all_pages(
                'ec2', region, self.session, 'describe_security_groups', 'SecurityGroups', Filters=filters)
        except Exception as e:
            print_exception(f'Failed to describe EC2 security groups: {e}')
            return []

    async def get_vpcs(self, region: str):
        ec2_client = AWSFacadeUtils.get_client('ec2', self.session, region)
        try:
            return await run_concurrently(lambda: ec2_client.describe_vpcs()['Vpcs'])
        except Exception as e:
            print_exception(f'Failed to describe EC2 VPC: {e}')
            return []

    async def get_images(self, region: str):
        filters = [{'Name': 'owner-id', 'Values': [self.owner_id]}]
        client = AWSFacadeUtils.get_client('ec2', self.session, region)
        try:
            return await run_concurrently(lambda: client.describe_images(Filters=filters)['Images'])
        except Exception as e:
            print_exception(f'Failed to get EC2 images: {e}')
            return []

    async def get_network_interfaces(self, region: str, vpc: str):
        filters = [{'Name': 'vpc-id', 'Values': [vpc]}]
        try:
            return await AWSFacadeUtils.get_all_pages(
                'ec2', region, self.session, 'describe_network_interfaces', 'NetworkInterfaces', Filters=filters)
        except Exception as e:
            print_exception(f'Failed to get EC2 network interfaces: {e}')
            return []

    async def get_volumes(self, region: str):
        try:
            volumes = await AWSFacadeUtils.get_all_pages('ec2', region, self.session, 'describe_volumes', 'Volumes')
            await get_and_set_concurrently([self._get_and_set_key_manager], volumes, region=region)
            return volumes
        except Exception as e:
            print_exception(f'Failed to get EC2 volumes: {e}')
            return []

    async def _get_and_set_key_manager(self, volume: {}, region: str):
        kms_client = AWSFacadeUtils.get_client('kms', self.session, region)
        if 'KmsKeyId' in volume:
            key_id = volume['KmsKeyId']
            try:
                volume['KeyManager'] = await run_concurrently(
                    lambda: kms_client.describe_key(KeyId=key_id)['KeyMetadata']['KeyManager'])
            except Exception as e:
                if 'NotFoundException' in e:
                    print_warning(f'Failed to describe KMS key: {e}')
                else:
                    print_exception(f'Failed to describe KMS key: {e}')
                volume['KeyManager'] = None
        else:
            volume['KeyManager'] = None

    async def get_snapshots(self, region: str):
        filters = [{'Name': 'owner-id', 'Values': [self.owner_id]}]

        try:
            snapshots = await AWSFacadeUtils.get_all_pages(
                'ec2', region, self.session, 'describe_snapshots', 'Snapshots', Filters=filters)
        except Exception as e:
            print_exception(f'Failed to get snapshots: {e}')
            snapshots = []
        else:
            await get_and_set_concurrently([self._get_and_set_snapshot_attributes], snapshots, region=region)
        finally:
            return snapshots

    async def _get_and_set_snapshot_attributes(self, snapshot: {}, region: str):
        ec2_client = AWSFacadeUtils.get_client('ec2', self.session, region)
        try:
            snapshot['CreateVolumePermissions'] = await run_concurrently(lambda: ec2_client.describe_snapshot_attribute(
                Attribute='createVolumePermission',
                SnapshotId=snapshot['SnapshotId'])['CreateVolumePermissions'])
        except Exception as e:
            if 'NotFound' in e:
                print_warning(f'Failed to describe EC2 snapshot attributes: {e}')
            else:
                print_exception(f'Failed to describe EC2 snapshot attributes: {e}')

    async def get_network_acls(self, region: str, vpc: str):
        filters = [{'Name': 'vpc-id', 'Values': [vpc]}]
        try:
            return await AWSFacadeUtils.get_all_pages(
                'ec2', region, self.session, 'describe_network_acls', 'NetworkAcls', Filters=filters)
        except Exception as e:
            print_exception(f'Failed to get EC2 network ACLs: {e}')
            return []

    async def get_flow_logs(self, region: str):
        try:
            await self.cache_flow_logs(region)
            return self.flow_logs_cache[region]
        except Exception as e:
            print_exception(f'Failed to get EC2 flow logs: {e}')
            return []

    async def cache_flow_logs(self, region: str):
        async with self.regional_flow_logs_cache_locks.setdefault(region, asyncio.Lock()):
            if region in self.flow_logs_cache:
                return

            self.flow_logs_cache[region] = \
                await AWSFacadeUtils.get_all_pages('ec2', region, self.session, 'describe_flow_logs', 'FlowLogs')

    async def get_subnets(self, region: str, vpc: str):
        ec2_client = AWSFacadeUtils.get_client('ec2', self.session, region)
        filters = [{'Name': 'vpc-id', 'Values': [vpc]}]
        try:
            subnets = await run_concurrently(lambda: ec2_client.describe_subnets(Filters=filters)['Subnets'])
        except Exception as e:
            print_exception(f'Failed to describe EC2 subnets: {e}')
            return None
        else:
            await get_and_set_concurrently(
                [self._get_and_set_subnet_flow_logs, self._get_and_set_subnet_route_table],
                subnets, region=region)
            return subnets

    async def _get_and_set_subnet_flow_logs(self, subnet: {}, region: str):
        await self.cache_flow_logs(region)
        subnet['flow_logs'] = \
            [flow_log for flow_log in self.flow_logs_cache[region]
             if flow_log['ResourceId'] == subnet['SubnetId'] or flow_log['ResourceId'] == subnet['VpcId']]

    async def _get_and_set_subnet_route_table(self, subnet: {}, region: str):
        """The route table that actually decides where the subnet's traffic goes: the one explicitly
        associated with it, or, when it has none, the main route table of its VPC. Which one applies
        is what makes the subnet public or private, and AWS reports it nowhere on the subnet."""

        route_tables = await self.get_route_tables(region, subnet['VpcId'])

        explicit_table = next(
            (route_table for route_table in route_tables
             if any(association.get('SubnetId') == subnet['SubnetId']
                    for association in route_table.get('Associations', []))), None)
        main_table = next(
            (route_table for route_table in route_tables
             if any(association.get('Main') for association in route_table.get('Associations', []))), None)

        subnet['route_table'] = explicit_table or main_table

    async def get_peering_connections(self, region):
        try:
            peering_connections = await AWSFacadeUtils.get_all_pages('ec2', region, self.session, 'describe_vpc_peering_connections', 'VpcPeeringConnections')
            return peering_connections
        except Exception as e:
            print_exception(f'Failed to get peering connections: {e}')
            return []

    async def get_vpc_endpoints(self, region):
        try:
            return await AWSFacadeUtils.get_all_pages(
                'ec2', region, self.session, 'describe_vpc_endpoints', 'VpcEndpoints')
        except Exception as e:
            print_exception(f'Failed to get VPC endpoints: {e}')
            return []

    async def get_route_tables(self, region: str, vpc: str = None):
        """Route tables of a region, or of a single VPC. They are read once per region and cached,
        as both the route table resources and every subnet of the region need them."""

        try:
            await self.cache_route_tables(region)
        except Exception as e:
            print_exception(f'Failed to get EC2 route tables: {e}')
            return []

        route_tables = self.route_tables_cache[region]
        if vpc:
            return [route_table for route_table in route_tables if route_table.get('VpcId') == vpc]
        return route_tables

    async def cache_route_tables(self, region: str):
        async with self.regional_route_tables_cache_locks.setdefault(region, asyncio.Lock()):
            if region in self.route_tables_cache:
                return

            self.route_tables_cache[region] = \
                await AWSFacadeUtils.get_all_pages(
                    'ec2', region, self.session, 'describe_route_tables', 'RouteTables')

    async def get_launch_templates(self, region: str):
        try:
            launch_templates = await AWSFacadeUtils.get_all_pages(
                'ec2', region, self.session, 'describe_launch_templates', 'LaunchTemplates')
        except Exception as e:
            print_exception(f'Failed to describe EC2 launch templates: {e}')
            return []

        await get_and_set_concurrently(
            [self._get_and_set_launch_template_versions], launch_templates, region=region)

        return launch_templates

    async def _get_and_set_launch_template_versions(self, launch_template: {}, region: str):
        """Read the two versions of a template that decide what actually gets launched: the default
        one, which is what a request naming no version gets, and the latest one, which is what
        anything following $Latest gets. The intermediate versions are left alone, a template can
        hold thousands of them and none of them is in force."""

        try:
            versions = await AWSFacadeUtils.get_all_pages(
                'ec2', region, self.session, 'describe_launch_template_versions', 'LaunchTemplateVersions',
                LaunchTemplateId=launch_template['LaunchTemplateId'], Versions=['$Default', '$Latest'])
        except Exception as e:
            print_exception(f'Failed to describe EC2 launch template versions: {e}')
            return

        # A template whose default version is also its latest one is returned twice
        launch_template['Versions'] = list(
            {version['VersionNumber']: version for version in versions}.values())

        for version in launch_template['Versions']:
            user_data = (version.get('LaunchTemplateData') or {}).get('UserData')
            if not user_data:
                continue
            try:
                version['user_data'] = decode_user_data(user_data)
            except Exception as e:
                print_exception(f'Unable to decode EC2 launch template user data: {e}')

    async def get_ebs_encryption(self, region):
        ec2_client = AWSFacadeUtils.get_client('ec2', self.session, region)
        try:
            encryption_settings = await run_concurrently(lambda: ec2_client.get_ebs_encryption_by_default())
            return encryption_settings
        except Exception as e:
            print_exception(f'Failed to retrieve EBS encryption settings: {e}')

    async def get_instance_metadata_defaults(self, region):
        """The IMDS settings the region applies to instances launched without any of their own.
        Without them, a launch template that leaves MetadataOptions out cannot be read either way."""

        ec2_client = AWSFacadeUtils.get_client('ec2', self.session, region)
        try:
            response = await run_concurrently(lambda: ec2_client.get_instance_metadata_defaults())
            return response.get('AccountLevel') or {}
        except Exception as e:
            print_exception(f'Failed to retrieve EC2 instance metadata defaults: {e}')
            return {}

    async def get_ebs_default_encryption_key(self, region):
        ec2_client = AWSFacadeUtils.get_client('ec2', self.session, region)
        try:
            encryption_key = await run_concurrently(lambda: ec2_client.get_ebs_default_kms_key_id())
            return encryption_key
        except Exception as e:
            print_exception(f'Failed to retrieve EBS encryption key ID: {e}')
