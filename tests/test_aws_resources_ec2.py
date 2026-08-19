import unittest

from datetime import datetime

from ScoutSuite.providers.aws.resources.ec2.elastic_ips import ElasticIPs
from ScoutSuite.providers.aws.resources.ec2.launchtemplates import LaunchTemplates


class Facade:
    partition = 'aws'
    owner_id = '123456789012'


def parse_version(launch_template_data, **version_attributes):
    raw_version = {'VersionNumber': 1, 'LaunchTemplateData': launch_template_data}
    raw_version.update(version_attributes)
    return LaunchTemplates(Facade(), 'eu-west-1')._parse_version(raw_version)


class TestAWSLaunchTemplateMetadataOptions(unittest.TestCase):

    def test_imdsv2_required(self):
        version = parse_version({'MetadataOptions': {'HttpTokens': 'required',
                                                     'HttpEndpoint': 'enabled',
                                                     'HttpPutResponseHopLimit': 1}})

        assert version['imdsv2_required'] is True
        assert version['imds_hop_limit_excessive'] is False
        assert version['http_tokens'] == 'required'
        assert version['metadata_http_endpoint'] == 'enabled'

    def test_imdsv2_optional(self):
        version = parse_version({'MetadataOptions': {'HttpTokens': 'optional'}})

        assert version['imdsv2_required'] is False
        assert version['http_tokens'] == 'optional'

    def test_metadata_options_left_out(self):
        # The version enforces nothing of its own, what the instances get is decided by the AMI and
        # by the instance metadata defaults of the region
        version = parse_version({'ImageId': 'ami-01234567890123456'})

        assert version['imdsv2_required'] is False
        assert version['http_tokens'] is None
        assert version['http_put_response_hop_limit'] is None
        assert version['imds_hop_limit_excessive'] is False

    def test_hop_limit_beyond_the_instance(self):
        version = parse_version({'MetadataOptions': {'HttpTokens': 'required',
                                                     'HttpPutResponseHopLimit': 2}})

        assert version['imds_hop_limit_excessive'] is True
        assert version['http_put_response_hop_limit'] == 2


class TestAWSLaunchTemplateNetwork(unittest.TestCase):

    def test_public_address_requested(self):
        version = parse_version({'NetworkInterfaces': [
            {'DeviceIndex': 0, 'AssociatePublicIpAddress': True, 'Groups': ['sg-1']}]})

        assert version['associate_public_ip_address'] is True
        assert version['security_groups'] == ['sg-1']

    def test_public_address_refused(self):
        version = parse_version({'NetworkInterfaces': [
            {'DeviceIndex': 0, 'AssociatePublicIpAddress': False}]})

        assert version['associate_public_ip_address'] is False

    def test_public_address_on_a_secondary_interface(self):
        version = parse_version({'NetworkInterfaces': [
            {'DeviceIndex': 0, 'AssociatePublicIpAddress': False},
            {'DeviceIndex': 1, 'AssociatePublicIpAddress': True}]})

        assert version['associate_public_ip_address'] is True

    def test_no_network_interface_leaves_the_subnet_to_decide(self):
        version = parse_version({'SecurityGroupIds': ['sg-1', 'sg-2']})

        assert version['associate_public_ip_address'] is None
        assert version['security_groups'] == ['sg-1', 'sg-2']
        assert version['network_interfaces'] == []


class TestAWSLaunchTemplateBlockDevices(unittest.TestCase):

    def test_encryption_refused_explicitly(self):
        version = parse_version({'BlockDeviceMappings': [
            {'DeviceName': '/dev/xvda', 'Ebs': {'Encrypted': False, 'VolumeSize': 8}}]})

        assert version['unencrypted_block_devices'] == ['/dev/xvda']

    def test_encryption_requested(self):
        version = parse_version({'BlockDeviceMappings': [
            {'DeviceName': '/dev/xvda', 'Ebs': {'Encrypted': True, 'KmsKeyId': 'key-1'}}]})

        assert version['unencrypted_block_devices'] == []
        assert version['block_devices'][0]['kms_key_id'] == 'key-1'

    def test_encryption_left_unspecified(self):
        # The volume inherits the encryption of its snapshot and the default of the region, which is
        # not the same thing as asking for an unencrypted one
        version = parse_version({'BlockDeviceMappings': [
            {'DeviceName': '/dev/xvda', 'Ebs': {'VolumeSize': 8}}]})

        assert version['unencrypted_block_devices'] == []
        assert version['block_devices'][0]['encrypted'] is None

    def test_instance_store_mapping_is_not_a_volume(self):
        version = parse_version({'BlockDeviceMappings': [
            {'DeviceName': '/dev/sdb', 'VirtualName': 'ephemeral0'}]})

        assert version['block_devices'] == []
        assert version['unencrypted_block_devices'] == []


class TestAWSLaunchTemplateVersion(unittest.TestCase):

    def test_user_data_secrets(self):
        version = parse_version(
            {'UserData': 'aWdub3JlZA=='},
            user_data='export AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF\n')

        assert version['user_data_secrets']['AWS Access Key IDs'] == ['AKIA0123456789ABCDEF']

    def test_no_user_data(self):
        version = parse_version({'ImageId': 'ami-01234567890123456'})

        assert version['user_data'] is None
        assert version['user_data_secrets'] == {}

    def test_iam_role_read_from_the_profile_arn(self):
        version = parse_version({'IamInstanceProfile': {
            'Arn': 'arn:aws:iam::123456789012:instance-profile/web'}})

        assert version['iam_role'] == 'web'

    def test_iam_role_read_from_the_profile_name(self):
        version = parse_version({'IamInstanceProfile': {'Name': 'web'}})

        assert version['iam_role'] == 'web'


class TestAWSLaunchTemplate(unittest.TestCase):

    @staticmethod
    def _parse(**attributes):
        raw_launch_template = {
            'LaunchTemplateId': 'lt-01234567890123456',
            'LaunchTemplateName': 'web',
            'CreateTime': datetime(2025, 3, 4, 9, 15, 0),
            'DefaultVersionNumber': 1,
            'LatestVersionNumber': 1,
        }
        raw_launch_template.update(attributes)
        return LaunchTemplates(Facade(), 'eu-west-1')._parse_launch_template(raw_launch_template)

    def test_template_without_collected_versions(self):
        key, launch_template = self._parse()

        assert key == 'lt-01234567890123456'
        assert launch_template['arn'] == \
            'arn:aws:ec2:eu-west-1:123456789012:launch-template/lt-01234567890123456'
        assert launch_template['create_time'] == '2025-03-04 09:15:00'
        assert launch_template['default_version_is_latest'] is True
        assert launch_template['versions'] == {}

    def test_versions_are_keyed_by_version_number(self):
        _, launch_template = self._parse(
            DefaultVersionNumber=2, LatestVersionNumber=7,
            Versions=[{'VersionNumber': 2, 'DefaultVersion': True, 'LaunchTemplateData': {}},
                      {'VersionNumber': 7, 'DefaultVersion': False, 'LaunchTemplateData': {}}])

        assert sorted(launch_template['versions']) == ['2', '7']
        assert launch_template['versions']['2']['is_default'] is True
        assert launch_template['versions']['7']['is_default'] is False
        # What was hardened in the latest version is not what the instances get
        assert launch_template['default_version_is_latest'] is False


def parse_elastic_ip(**attributes):
    raw_elastic_ip = {'PublicIp': '203.0.113.10', 'Domain': 'vpc'}
    raw_elastic_ip.update(attributes)
    return ElasticIPs(Facade(), 'eu-west-1')._parse_elastic_ip(raw_elastic_ip)


class TestAWSElasticIPs(unittest.TestCase):

    def test_address_attached_to_an_instance(self):
        key, elastic_ip = parse_elastic_ip(
            AllocationId='eipalloc-01234567890123456',
            AssociationId='eipassoc-01234567890123456',
            InstanceId='i-01234567890123456',
            NetworkInterfaceId='eni-01234567890123456',
            PrivateIpAddress='10.0.1.10',
            Tags=[{'Key': 'Name', 'Value': 'web-1'}])

        assert key == 'eipalloc-01234567890123456'
        assert elastic_ip['name'] == 'web-1'
        assert elastic_ip['arn'] == \
            'arn:aws:ec2:eu-west-1:123456789012:elastic-ip/eipalloc-01234567890123456'
        assert elastic_ip['associated'] is True
        assert elastic_ip['instance_id'] == 'i-01234567890123456'
        assert elastic_ip['private_ip_address'] == '10.0.1.10'

    def test_address_attached_to_nothing(self):
        key, elastic_ip = parse_elastic_ip(AllocationId='eipalloc-01234567890123456')

        assert elastic_ip['associated'] is False
        assert elastic_ip['instance_id'] is None
        assert elastic_ip['network_interface_id'] is None
        # With no Name tag the address itself is the name
        assert elastic_ip['name'] == '203.0.113.10'

    def test_address_attached_to_an_interface_with_no_instance(self):
        # A NAT gateway or a load balancer address: attached, with nothing in the account owning the
        # attachment
        key, elastic_ip = parse_elastic_ip(
            AllocationId='eipalloc-01234567890123456',
            AssociationId='eipassoc-01234567890123456',
            NetworkInterfaceId='eni-01234567890123456',
            ServiceManaged='nat-gateway')

        assert elastic_ip['associated'] is True
        assert elastic_ip['instance_id'] is None
        assert elastic_ip['service_managed'] == 'nat-gateway'

    def test_ec2_classic_address_is_keyed_by_its_public_ip(self):
        key, elastic_ip = parse_elastic_ip(Domain='standard', InstanceId='')

        assert key == '203.0.113.10'
        assert elastic_ip['allocation_id'] is None
        # DescribeAddresses reports an empty instance id rather than none for a detached one
        assert elastic_ip['instance_id'] is None
        assert elastic_ip['associated'] is False
