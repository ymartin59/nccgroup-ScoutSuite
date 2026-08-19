from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.utils import format_arn, identify_user_data_secrets


class LaunchTemplates(AWSResources):
    """The EC2 launch templates of a region, with the two versions that decide what actually gets
    launched: the default one, used by a request that names no version, and the latest one, used by
    anything following $Latest. Every instance an Auto Scaling group, a Spot fleet or a console
    launch creates is built from one of these, so the settings collected here are the ones the
    instances that do not exist yet will have."""

    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region
        self.partition = facade.partition
        self.owner_id = facade.owner_id

    async def fetch_all(self):
        for raw_launch_template in await self.facade.ec2.get_launch_templates(self.region):
            name, resource = self._parse_launch_template(raw_launch_template)
            self[name] = resource

    def _parse_launch_template(self, raw_launch_template):
        create_time = raw_launch_template.get('CreateTime')
        template_id = raw_launch_template['LaunchTemplateId']

        launch_template = {}
        launch_template['id'] = template_id
        launch_template['name'] = raw_launch_template.get('LaunchTemplateName', template_id)
        launch_template['arn'] = format_arn(
            self.partition, 'ec2', self.region, self.owner_id, template_id, 'launch-template')
        launch_template['region'] = self.region
        launch_template['create_time'] = create_time.strftime('%Y-%m-%d %H:%M:%S') if create_time else None
        launch_template['created_by'] = raw_launch_template.get('CreatedBy')
        launch_template['default_version_number'] = raw_launch_template.get('DefaultVersionNumber')
        launch_template['latest_version_number'] = raw_launch_template.get('LatestVersionNumber')
        # A default version left behind the latest one means whoever hardened the template did not
        # make the result the one instances get
        launch_template['default_version_is_latest'] = \
            launch_template['default_version_number'] == launch_template['latest_version_number']
        launch_template['tags'] = raw_launch_template.get('Tags') or []

        launch_template['versions'] = {}
        for raw_version in raw_launch_template.get('Versions') or []:
            version = self._parse_version(raw_version)
            launch_template['versions'][str(version['version_number'])] = version

        return template_id, launch_template

    def _parse_version(self, raw_version):
        data = raw_version.get('LaunchTemplateData') or {}
        create_time = raw_version.get('CreateTime')

        version = {}
        version['id'] = str(raw_version.get('VersionNumber'))
        version['version_number'] = raw_version.get('VersionNumber')
        version['name'] = f'Version {version["version_number"]}'
        version['description'] = raw_version.get('VersionDescription')
        version['is_default'] = bool(raw_version.get('DefaultVersion'))
        version['create_time'] = create_time.strftime('%Y-%m-%d %H:%M:%S') if create_time else None
        version['created_by'] = raw_version.get('CreatedBy')

        version['image_id'] = data.get('ImageId')
        version['instance_type'] = data.get('InstanceType')
        version['key_name'] = data.get('KeyName')
        version['ebs_optimized'] = data.get('EbsOptimized')
        version['monitoring_enabled'] = (data.get('Monitoring') or {}).get('Enabled')
        version['tenancy'] = (data.get('Placement') or {}).get('Tenancy')
        version['disable_api_termination'] = data.get('DisableApiTermination')
        version['disable_api_stop'] = data.get('DisableApiStop')

        iam_instance_profile = data.get('IamInstanceProfile') or {}
        version['iam_instance_profile_arn'] = iam_instance_profile.get('Arn')
        version['iam_instance_profile_name'] = iam_instance_profile.get('Name')
        version['iam_role'] = \
            iam_instance_profile.get('Name') or \
            (iam_instance_profile['Arn'].split('/')[-1] if iam_instance_profile.get('Arn') else None)

        # User data is carried by the template, so a secret written into it is handed to every
        # instance the template ever launches, and read by anyone reaching the metadata service
        version['user_data'] = raw_version.get('user_data')
        version['user_data_secrets'] = identify_user_data_secrets(version['user_data'])

        self._parse_network(data, version)
        self._parse_metadata_options(data, version)
        self._parse_block_devices(data, version)

        return version

    @staticmethod
    def _parse_network(data, version):
        network_interfaces = data.get('NetworkInterfaces') or []

        version['network_interfaces'] = [
            {
                'device_index': interface.get('DeviceIndex'),
                'subnet_id': interface.get('SubnetId'),
                'associate_public_ip_address': interface.get('AssociatePublicIpAddress'),
                'security_groups': interface.get('Groups') or [],
            }
            for interface in network_interfaces
        ]

        # Security groups may be named at the top level or on each network interface, and the two
        # are mutually exclusive in a single template
        version['security_groups'] = (data.get('SecurityGroupIds') or []) + [
            group for interface in network_interfaces for group in interface.get('Groups') or []]
        version['security_group_names'] = data.get('SecurityGroups') or []

        # A template that defines no network interface says nothing about public addressing, the
        # subnet the instance lands in decides it, which is left as unknown rather than as disabled
        if not network_interfaces:
            version['associate_public_ip_address'] = None
        else:
            version['associate_public_ip_address'] = \
                any(interface.get('AssociatePublicIpAddress') for interface in network_interfaces)

    @staticmethod
    def _parse_metadata_options(data, version):
        metadata_options = data.get('MetadataOptions') or {}
        http_tokens = metadata_options.get('HttpTokens')
        hop_limit = metadata_options.get('HttpPutResponseHopLimit')

        version['metadata_options'] = metadata_options
        version['http_tokens'] = http_tokens
        version['metadata_http_endpoint'] = metadata_options.get('HttpEndpoint')
        version['metadata_tags_enabled'] = metadata_options.get('InstanceMetadataTags') == 'enabled'
        version['http_put_response_hop_limit'] = hop_limit
        # A template that says nothing leaves the choice to the AMI and to the instance metadata
        # defaults of the region, so it does not require IMDSv2 by itself either
        version['imdsv2_required'] = http_tokens == 'required'
        # One hop reaches the instance and nothing else. Beyond that the metadata service, and the
        # credentials of the instance profile it hands out, answer containers and any process able
        # to make the instance forward a request
        version['imds_hop_limit_excessive'] = hop_limit is not None and hop_limit > 1

    @staticmethod
    def _parse_block_devices(data, version):
        block_devices = []
        for mapping in data.get('BlockDeviceMappings') or []:
            ebs = mapping.get('Ebs')
            if not ebs:
                continue
            block_devices.append({
                'device_name': mapping.get('DeviceName'),
                'encrypted': ebs.get('Encrypted'),
                'kms_key_id': ebs.get('KmsKeyId'),
                'volume_type': ebs.get('VolumeType'),
                'volume_size': ebs.get('VolumeSize'),
                'delete_on_termination': ebs.get('DeleteOnTermination'),
            })

        version['block_devices'] = block_devices
        # Only an explicit false is reported: a mapping that leaves Encrypted out inherits the
        # encryption of the snapshot it comes from and the default of the region, which the
        # ec2-ebs-default-encryption-disabled rule covers on its own
        version['unencrypted_block_devices'] = \
            [device['device_name'] for device in block_devices if device['encrypted'] is False]
