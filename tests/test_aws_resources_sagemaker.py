import unittest
from datetime import datetime

from ScoutSuite.providers.aws.resources.sagemaker.domains import Domains
from ScoutSuite.providers.aws.resources.sagemaker.endpoints import Endpoints
from ScoutSuite.providers.aws.resources.sagemaker.models import Models
from ScoutSuite.providers.aws.resources.sagemaker.notebook_instances import NotebookInstances
from ScoutSuite.providers.aws.resources.sagemaker.training_jobs import TrainingJobs


class TestAWSSageMakerNotebookNetwork(unittest.TestCase):

    @staticmethod
    def _parse(raw_notebook_instance):
        notebook_instance = {}
        NotebookInstances._parse_network(raw_notebook_instance, notebook_instance)
        return notebook_instance

    def test_notebook_in_a_subnet_of_the_account(self):
        notebook_instance = self._parse({
            'SubnetId': 'subnet-0a1b2c3d',
            'SecurityGroups': ['sg-0a1b2c3d'],
            'DirectInternetAccess': 'Disabled',
        })

        assert notebook_instance['in_customer_vpc'] is True
        assert notebook_instance['direct_internet_access_enabled'] is False

    def test_notebook_without_a_subnet(self):
        # No subnet means the notebook runs in a VPC SageMaker owns, where nothing the account
        # writes applies to it
        notebook_instance = self._parse({'DirectInternetAccess': 'Enabled'})

        assert notebook_instance['in_customer_vpc'] is False
        assert notebook_instance['security_groups'] == []

    def test_direct_internet_access_absent_from_the_description(self):
        # Enabled is what SageMaker applies when the creation request says nothing
        notebook_instance = self._parse({'SubnetId': 'subnet-0a1b2c3d'})

        assert notebook_instance['direct_internet_access'] is None
        assert notebook_instance['direct_internet_access_enabled'] is True

    def test_notebook_in_a_vpc_with_direct_internet_access(self):
        # The two settings are independent: SageMaker attaches an interface with a public route of
        # its own, so a notebook in a private subnet can still reach the internet
        notebook_instance = self._parse({
            'SubnetId': 'subnet-0a1b2c3d',
            'DirectInternetAccess': 'Enabled',
        })

        assert notebook_instance['in_customer_vpc'] is True
        assert notebook_instance['direct_internet_access_enabled'] is True


class TestAWSSageMakerNotebookAccess(unittest.TestCase):

    @staticmethod
    def _parse(raw_notebook_instance):
        notebook_instance = {}
        NotebookInstances._parse_access(raw_notebook_instance, notebook_instance)
        return notebook_instance

    def test_root_access_disabled(self):
        notebook_instance = self._parse({'RootAccess': 'Disabled'})

        assert notebook_instance['root_access_enabled'] is False

    def test_root_access_absent_from_the_description(self):
        # Enabled is what SageMaker applies when the creation request says nothing
        notebook_instance = self._parse({})

        assert notebook_instance['root_access_enabled'] is True

    def test_imdsv2_required(self):
        notebook_instance = self._parse({
            'InstanceMetadataServiceConfiguration': {'MinimumInstanceMetadataServiceVersion': '2'}})

        assert notebook_instance['imdsv2_required'] is True

    def test_imdsv1_permitted(self):
        notebook_instance = self._parse({
            'InstanceMetadataServiceConfiguration': {'MinimumInstanceMetadataServiceVersion': '1'}})

        assert notebook_instance['imdsv2_required'] is False

    def test_platform_predating_the_setting(self):
        # A notebook whose platform reports no configuration answers IMDSv1 requests, so the absent
        # block is read as v1 permitted rather than as unknown
        notebook_instance = self._parse({})

        assert notebook_instance['imds_minimum_version'] is None
        assert notebook_instance['imdsv2_required'] is False


class TestAWSSageMakerDomain(unittest.TestCase):

    @staticmethod
    def _parse(raw_domain):
        domain = {}
        Domains._parse_network(raw_domain, domain)
        Domains._parse_encryption(raw_domain, domain)
        Domains._parse_default_user_settings(raw_domain, domain)
        Domains._parse_domain_settings(raw_domain, domain)
        Domains._parse_user_profiles(raw_domain, domain)
        return domain

    def test_vpc_only_domain(self):
        domain = self._parse({
            'AppNetworkAccessType': 'VpcOnly',
            'VpcId': 'vpc-0a1b2c3d',
            'SubnetIds': ['subnet-0a1b2c3d'],
            'KmsKeyId': 'arn:aws:kms:eu-west-1:123456789012:key/abcd1234',
            'DomainSettings': {'ExecutionRoleIdentityConfig': 'USER_PROFILE_NAME'},
        })

        assert domain['vpc_only_access'] is True
        assert domain['encryption_with_cmk'] is True
        assert domain['user_identity_propagated'] is True

    def test_network_access_absent_from_the_description(self):
        # PublicInternetOnly is what SageMaker applies when the creation request says nothing
        domain = self._parse({})

        assert domain['app_network_access_type'] is None
        assert domain['vpc_only_access'] is False
        assert domain['encryption_with_cmk'] is False
        assert domain['user_identity_propagated'] is False

    def test_deprecated_home_efs_key_name(self):
        # Domains created before the key was renamed are still described with the old name
        domain = self._parse({
            'HomeEfsFileSystemKmsKeyId': 'arn:aws:kms:eu-west-1:123456789012:key/abcd1234'})

        assert domain['encryption_with_cmk'] is True

    def test_notebook_output_sharing(self):
        domain = self._parse({'DefaultUserSettings': {'SharingSettings': {
            'NotebookOutputOption': 'Allowed',
            'S3OutputPath': 's3://sharing/',
        }}})

        assert domain['notebook_output_sharing_enabled'] is True
        assert domain['notebook_sharing_s3_path'] == 's3://sharing/'

    def test_user_profile_overriding_the_domain_role(self):
        domain = self._parse({
            'DefaultUserSettings': {'ExecutionRole': 'arn:aws:iam::123456789012:role/Default'},
            'user_profile_details': [
                {
                    'UserProfileName': 'alice',
                    'Status': 'InService',
                    'CreationTime': datetime(2023, 2, 17, 8, 45, 0),
                    'UserSettings': {'ExecutionRole': 'arn:aws:iam::123456789012:role/PowerUser'},
                },
                {
                    'UserProfileName': 'bob',
                    'Status': 'InService',
                    'UserSettings': {},
                },
            ],
        })

        assert domain['user_profiles_count'] == 2
        alice = domain['user_profiles']['alice']
        assert alice['execution_role'] == 'arn:aws:iam::123456789012:role/PowerUser'
        assert alice['execution_role_overridden'] is True
        assert alice['creation_time'] == '2023-02-17 08:45:00'
        # A profile that declares no role of its own runs as the domain default, which is not an
        # override
        bob = domain['user_profiles']['bob']
        assert bob['execution_role'] == 'arn:aws:iam::123456789012:role/Default'
        assert bob['execution_role_overridden'] is False


class TestAWSSageMakerEndpoint(unittest.TestCase):

    @staticmethod
    def _parse(raw_endpoint):
        endpoint = {}
        Endpoints._parse_configuration(raw_endpoint, endpoint)
        Endpoints._parse_variants(raw_endpoint, endpoint)
        Endpoints._parse_data_capture(raw_endpoint, endpoint)
        return endpoint

    def test_settings_read_from_the_endpoint_configuration(self):
        endpoint = self._parse({'endpoint_config': {
            'KmsKeyId': 'arn:aws:kms:eu-west-1:123456789012:key/abcd1234',
            'EnableNetworkIsolation': True,
            'VpcConfig': {'Subnets': ['subnet-0a1b2c3d'], 'SecurityGroupIds': ['sg-0a1b2c3d']},
            'ExecutionRoleArn': 'arn:aws:iam::123456789012:role/Hosting',
        }})

        assert endpoint['encryption_with_cmk'] is True
        assert endpoint['network_isolation'] is True
        assert endpoint['in_customer_vpc'] is True

    def test_configuration_that_could_not_be_read(self):
        # A denied DescribeEndpointConfig must not read as an unencrypted endpoint outside a VPC
        endpoint = self._parse({'EndpointConfigName': 'a-config'})

        assert endpoint['encryption_with_cmk'] is None
        assert endpoint['network_isolation'] is None
        assert endpoint['in_customer_vpc'] is None

    def test_single_instance_variant(self):
        endpoint = self._parse({
            'ProductionVariants': [{
                'VariantName': 'primary',
                'CurrentInstanceCount': 1,
                'DesiredInstanceCount': 1,
                'InstanceType': 'ml.c5.xlarge',
            }],
            'endpoint_config': {'ProductionVariants': [
                {'VariantName': 'primary', 'ModelName': 'a-model'}]},
        })

        variant = endpoint['production_variants']['primary']
        assert variant['single_instance'] is True
        # The model a variant serves is named by the configuration, not by the endpoint
        assert variant['model_name'] == 'a-model'

    def test_serverless_variant(self):
        # A serverless variant has no instances, so it is never a single point of failure
        endpoint = self._parse({
            'ProductionVariants': [{
                'VariantName': 'primary',
                'CurrentServerlessConfig': {'MemorySizeInMB': 2048, 'MaxConcurrency': 5},
            }],
        })

        variant = endpoint['production_variants']['primary']
        assert variant['serverless'] is True
        assert variant['single_instance'] is None

    def test_shadow_variants_are_collected_too(self):
        endpoint = self._parse({
            'ProductionVariants': [{'VariantName': 'primary', 'CurrentInstanceCount': 2}],
            'ShadowProductionVariants': [{'VariantName': 'shadow', 'CurrentInstanceCount': 1}],
        })

        assert endpoint['production_variants_count'] == 2
        assert endpoint['production_variants']['primary']['single_instance'] is False
        assert endpoint['production_variants']['shadow']['single_instance'] is True

    def test_data_capture_with_a_customer_managed_key(self):
        endpoint = self._parse({
            'DataCaptureConfig': {
                'EnableCapture': True,
                'CaptureStatus': 'Started',
                'CurrentSamplingPercentage': 100,
                'KmsKeyId': 'arn:aws:kms:eu-west-1:123456789012:key/abcd1234',
            },
            'endpoint_config': {'DataCaptureConfig': {'CaptureOptions': [{'CaptureMode': 'Input'}]}},
        })

        assert endpoint['data_capture_enabled'] is True
        assert endpoint['data_capture_encrypted_with_cmk'] is True
        assert endpoint['data_capture_options'] == ['Input']

    def test_data_capture_disabled(self):
        # There is nothing to encrypt when nothing is captured, so no decision is recorded
        endpoint = self._parse({'DataCaptureConfig': {'EnableCapture': False}})

        assert endpoint['data_capture_enabled'] is False
        assert endpoint['data_capture_encrypted_with_cmk'] is None

    def test_data_capture_without_a_key(self):
        endpoint = self._parse({
            'DataCaptureConfig': {'EnableCapture': True, 'DestinationS3Uri': 's3://capture/'}})

        assert endpoint['data_capture_encrypted_with_cmk'] is False


class ModelsStub(Models):
    """Models without a facade: the region it stamps on every resource is the only thing the parser
    reads off the instance."""

    def __init__(self):
        self.region = 'eu-west-1'


class TestAWSSageMakerModel(unittest.TestCase):

    @staticmethod
    def _parse(raw_model):
        return ModelsStub()._parse_model(dict(raw_model, ModelName='a-model'))[1]

    def test_isolated_model_in_a_vpc(self):
        model = self._parse({
            'EnableNetworkIsolation': True,
            'VpcConfig': {'Subnets': ['subnet-0a1b2c3d'], 'SecurityGroupIds': ['sg-0a1b2c3d']},
        })

        assert model['network_isolation'] is True
        assert model['in_customer_vpc'] is True

    def test_model_without_a_vpc_configuration(self):
        model = self._parse({})

        assert model['network_isolation'] is False
        assert model['in_customer_vpc'] is False

    def test_primary_container_comes_first(self):
        model = self._parse({
            'PrimaryContainer': {'Image': 'primary:1', 'Mode': 'SingleModel'},
            'Containers': [{'Image': 'sidecar:1'}],
        })

        assert model['containers_count'] == 2
        assert model['images'] == ['primary:1', 'sidecar:1']

    def test_only_the_environment_variable_names_are_kept(self):
        # The values carry credentials often enough that a shareable report must not hold them
        model = self._parse({'PrimaryContainer': {
            'Image': 'primary:1',
            'Environment': {'HF_TOKEN': 'hf_secret', 'SAGEMAKER_PROGRAM': 'inference.py'},
        }})

        container = model['containers'][0]
        assert container['environment_variable_names'] == ['HF_TOKEN', 'SAGEMAKER_PROGRAM']
        assert 'hf_secret' not in str(model)

    def test_artifact_from_a_model_data_source(self):
        model = self._parse({'PrimaryContainer': {
            'ModelDataSource': {'S3DataSource': {'S3Uri': 's3://artifacts/model/'}}}})

        assert model['containers'][0]['model_data_url'] == 's3://artifacts/model/'


class TestAWSSageMakerTrainingJob(unittest.TestCase):

    @staticmethod
    def _parse(resource_config, raw_training_job=None):
        training_job = {}
        TrainingJobs._parse_resources(training_job, resource_config)
        TrainingJobs._parse_encryption(
            raw_training_job or {}, training_job,
            (raw_training_job or {}).get('OutputDataConfig') or {}, resource_config)
        return training_job

    def test_single_instance_job_is_not_distributed(self):
        # A job on one instance has no traffic between containers to encrypt
        training_job = self._parse({'InstanceType': 'ml.m5.xlarge', 'InstanceCount': 1})

        assert training_job['instance_count'] == 1
        assert training_job['distributed'] is False

    def test_multi_instance_job_is_distributed(self):
        training_job = self._parse({'InstanceType': 'ml.m5.xlarge', 'InstanceCount': 4})

        assert training_job['distributed'] is True

    def test_heterogeneous_instance_groups(self):
        # A job declaring instance groups reports no top-level instance count, so the total has to
        # be summed over the groups or a distributed job would look like a single-instance one
        training_job = self._parse({'InstanceGroups': [
            {'InstanceGroupName': 'workers', 'InstanceType': 'ml.g5.2xlarge', 'InstanceCount': 2},
            {'InstanceGroupName': 'ps', 'InstanceType': 'ml.m5.large', 'InstanceCount': 1},
        ]})

        assert training_job['instance_count'] == 3
        assert training_job['distributed'] is True

    def test_encryption_of_the_three_places_the_data_rests(self):
        training_job = self._parse(
            {'InstanceCount': 2,
             'VolumeKmsKeyId': 'arn:aws:kms:eu-west-1:123456789012:key/abcd1234'},
            {'EnableInterContainerTrafficEncryption': True,
             'OutputDataConfig': {'KmsKeyId': 'arn:aws:kms:eu-west-1:123456789012:key/abcd1234'}})

        assert training_job['volume_encrypted_with_cmk'] is True
        assert training_job['output_encrypted_with_cmk'] is True
        assert training_job['inter_container_traffic_encryption'] is True

    def test_job_created_without_any_key(self):
        training_job = self._parse({'InstanceCount': 2}, {})

        assert training_job['volume_encrypted_with_cmk'] is False
        assert training_job['output_encrypted_with_cmk'] is False
        assert training_job['inter_container_traffic_encryption'] is False


if __name__ == '__main__':
    unittest.main()
