from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.utils import identify_user_data_secrets
from ScoutSuite.providers.utils import get_non_provider_id


class LaunchConfigurations(AWSResources):
    """The launch configurations of a region. AWS stopped offering them at the end of 2023 and they
    cannot be created any more, but a group still referencing one keeps launching instances from it,
    with settings that were fixed the day it was created and cannot be changed since."""

    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw_configuration in await self.facade.autoscaling.get_launch_configurations(self.region):
            name, resource = self._parse_launch_configuration(raw_configuration)
            self[name] = resource

    def _parse_launch_configuration(self, raw_configuration):
        created_time = raw_configuration.get('CreatedTime')

        configuration = {}
        configuration['id'] = raw_configuration['LaunchConfigurationName']
        configuration['name'] = raw_configuration['LaunchConfigurationName']
        configuration['arn'] = raw_configuration.get('LaunchConfigurationARN')
        configuration['region'] = self.region
        configuration['created_time'] = created_time.strftime('%Y-%m-%d %H:%M:%S') if created_time else None

        configuration['image_id'] = raw_configuration.get('ImageId')
        configuration['instance_type'] = raw_configuration.get('InstanceType')
        configuration['key_name'] = raw_configuration.get('KeyName')
        configuration['iam_instance_profile'] = raw_configuration.get('IamInstanceProfile')
        configuration['security_groups'] = raw_configuration.get('SecurityGroups') or []
        configuration['ebs_optimized'] = raw_configuration.get('EbsOptimized')
        configuration['monitoring_enabled'] = (raw_configuration.get('InstanceMonitoring') or {}).get('Enabled')
        configuration['placement_tenancy'] = raw_configuration.get('PlacementTenancy')
        configuration['spot_price'] = raw_configuration.get('SpotPrice')
        # Absent means the subnet decides, which is left as unknown rather than as disabled
        configuration['associate_public_ip_address'] = raw_configuration.get('AssociatePublicIpAddress')

        configuration['user_data'] = raw_configuration.get('user_data')
        configuration['user_data_secrets'] = identify_user_data_secrets(configuration['user_data'])

        self._parse_metadata_options(raw_configuration, configuration)
        self._parse_block_devices(raw_configuration, configuration)

        return get_non_provider_id(configuration['name']), configuration

    @staticmethod
    def _parse_metadata_options(raw_configuration, configuration):
        metadata_options = raw_configuration.get('MetadataOptions') or {}
        http_tokens = metadata_options.get('HttpTokens')
        hop_limit = metadata_options.get('HttpPutResponseHopLimit')

        configuration['metadata_options'] = metadata_options
        configuration['http_tokens'] = http_tokens
        configuration['metadata_http_endpoint'] = metadata_options.get('HttpEndpoint')
        configuration['http_put_response_hop_limit'] = hop_limit
        # A launch configuration cannot be edited, so one that does not require IMDSv2 will not
        # start doing so: the group has to be moved to a launch template that does
        configuration['imdsv2_required'] = http_tokens == 'required'
        configuration['imds_hop_limit_excessive'] = hop_limit is not None and hop_limit > 1

    @staticmethod
    def _parse_block_devices(raw_configuration, configuration):
        block_devices = []
        for mapping in raw_configuration.get('BlockDeviceMappings') or []:
            ebs = mapping.get('Ebs')
            if not ebs:
                continue
            block_devices.append({
                'device_name': mapping.get('DeviceName'),
                'encrypted': ebs.get('Encrypted'),
                'volume_type': ebs.get('VolumeType'),
                'volume_size': ebs.get('VolumeSize'),
                'delete_on_termination': ebs.get('DeleteOnTermination'),
            })

        configuration['block_devices'] = block_devices
        configuration['unencrypted_block_devices'] = \
            [device['device_name'] for device in block_devices if device['encrypted'] is False]
