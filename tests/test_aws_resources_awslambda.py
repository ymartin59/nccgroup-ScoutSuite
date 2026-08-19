import unittest

from ScoutSuite.providers.aws.resources.awslambda.functions import Functions
from ScoutSuite.providers.aws.resources.awslambda.layers import Layers
from ScoutSuite.providers.utils import get_non_provider_id


class Facade:
    partition = 'aws'
    owner_id = '123456789012'


def parse(parser, raw_function, **function_attributes):
    function = dict(function_attributes)
    parser(raw_function, function)
    return function


class TestAWSLambdaFunctionUrls(unittest.TestCase):

    def test_url_open_to_anyone(self):
        function = parse(Functions._parse_url_configs, {'url_configs': [{
            'FunctionUrl': 'https://abcdefghij.lambda-url.eu-west-1.on.aws/',
            'AuthType': 'NONE',
            'InvokeMode': 'RESPONSE_STREAM'}]})

        assert function['url_configured'] is True
        assert function['url_unauthenticated'] is True
        assert function['url_cors_allows_all_origins'] is False
        # A URL created without a qualifier serves the unpublished version
        assert function['url_configs']['$LATEST']['auth_type'] == 'NONE'
        assert function['url_configs']['$LATEST']['invoke_mode'] == 'RESPONSE_STREAM'

    def test_url_requiring_a_signature(self):
        function = parse(Functions._parse_url_configs, {'url_configs': [
            {'AuthType': 'AWS_IAM', 'Qualifier': 'live'}]})

        assert function['url_configured'] is True
        assert function['url_unauthenticated'] is False
        assert function['url_configs']['live']['invoke_mode'] == 'BUFFERED'

    def test_one_url_per_alias(self):
        # Every alias of a function can carry its own URL, with its own auth type
        function = parse(Functions._parse_url_configs, {'url_configs': [
            {'AuthType': 'AWS_IAM', 'Qualifier': 'live'},
            {'AuthType': 'NONE', 'Qualifier': 'canary'}]})

        assert function['url_unauthenticated'] is True
        assert sorted(function['url_configs']) == ['canary', 'live']

    def test_url_allowing_any_origin(self):
        function = parse(Functions._parse_url_configs, {'url_configs': [{
            'AuthType': 'AWS_IAM',
            'Cors': {'AllowOrigins': ['*'], 'AllowCredentials': True}}]})

        assert function['url_cors_allows_all_origins'] is True
        assert function['url_configs']['$LATEST']['cors_allow_credentials'] is True

    def test_url_with_an_origin_allowlist(self):
        function = parse(Functions._parse_url_configs, {'url_configs': [{
            'AuthType': 'AWS_IAM',
            'Cors': {'AllowOrigins': ['https://app.example.com']}}]})

        assert function['url_cors_allows_all_origins'] is False
        assert function['url_configs']['$LATEST']['cors_allow_credentials'] is False

    def test_function_without_a_url(self):
        function = parse(Functions._parse_url_configs, {})

        assert function['url_configs'] == {}
        assert function['url_configured'] is False
        assert function['url_unauthenticated'] is False
        assert function['url_cors_allows_all_origins'] is False


class TestAWSLambdaFunctionVpcConfig(unittest.TestCase):

    def test_function_attached_to_a_vpc(self):
        function = parse(Functions._parse_vpc_config, {'VpcConfig': {
            'VpcId': 'vpc-01234567890123456',
            'SubnetIds': ['subnet-01234567890123456'],
            'SecurityGroupIds': ['sg-01234567890123456']}})

        assert function['in_vpc'] is True
        assert function['vpc_config']['vpc_id'] == 'vpc-01234567890123456'
        assert function['vpc_config']['security_group_ids'] == ['sg-01234567890123456']

    def test_function_on_the_lambda_managed_network(self):
        # Lambda answers with an empty configuration rather than leaving the key out
        function = parse(Functions._parse_vpc_config, {'VpcConfig': {
            'SubnetIds': [], 'SecurityGroupIds': [], 'VpcId': ''}})

        assert function['in_vpc'] is False
        assert function['vpc_config']['subnet_ids'] == []

    def test_function_with_no_vpc_configuration_at_all(self):
        function = parse(Functions._parse_vpc_config, {})

        assert function['in_vpc'] is False
        assert function['vpc_config']['vpc_id'] is None


class TestAWSLambdaFunctionCodeSigning(unittest.TestCase):

    def test_code_signing_enforced(self):
        function = parse(Functions._parse_code_signing, {'code_signing_config': {
            'CodeSigningConfigArn': 'arn:aws:lambda:eu-west-1:123456789012:code-signing-config:csc-0123',
            'AllowedPublishers': {'SigningProfileVersionArns': [
                'arn:aws:signer:eu-west-1:123456789012:/signing-profiles/Release/9vT5NcJmAa']},
            'CodeSigningPolicies': {'UntrustedArtifactOnDeployment': 'Enforce'}}})

        assert function['code_signing_enabled'] is True
        assert function['code_signing_enforced'] is True
        assert function['code_signing_untrusted_artifact_policy'] == 'Enforce'
        assert len(function['code_signing_allowed_publishers']) == 1

    def test_code_signing_only_warning(self):
        # The signature is verified, the verdict is written to CloudTrail, and the package is
        # deployed either way
        function = parse(Functions._parse_code_signing, {'code_signing_config': {
            'CodeSigningConfigArn': 'arn:aws:lambda:eu-west-1:123456789012:code-signing-config:csc-0123',
            'CodeSigningPolicies': {'UntrustedArtifactOnDeployment': 'Warn'}}})

        assert function['code_signing_enabled'] is True
        assert function['code_signing_enforced'] is False
        assert function['code_signing_untrusted_artifact_policy'] == 'Warn'

    def test_function_without_a_code_signing_configuration(self):
        # A function can carry the signing profile of the package it was deployed with and still
        # have no configuration deciding what happens on the next deployment
        function = parse(Functions._parse_code_signing, {
            'SigningProfileVersionArn':
                'arn:aws:signer:eu-west-1:123456789012:/signing-profiles/Release/9vT5NcJmAa'})

        assert function['code_signing_enabled'] is False
        assert function['code_signing_enforced'] is False
        assert function['code_signing_untrusted_artifact_policy'] is None
        assert function['code_signing_allowed_publishers'] == []
        assert function['signing_profile_version_arn'] is not None


class TestAWSLambdaFunctionConcurrency(unittest.TestCase):

    def test_reserved_concurrency(self):
        function = parse(Functions._parse_concurrency, {'ReservedConcurrentExecutions': 25})

        assert function['reserved_concurrency'] == 25
        assert function['reserved_concurrency_configured'] is True

    def test_concurrency_reserved_to_zero(self):
        # Zero is a reservation like any other, and it is how a function is switched off
        function = parse(Functions._parse_concurrency, {'ReservedConcurrentExecutions': 0})

        assert function['reserved_concurrency'] == 0
        assert function['reserved_concurrency_configured'] is True

    def test_function_drawing_from_the_account_pool(self):
        function = parse(Functions._parse_concurrency, {})

        assert function['reserved_concurrency'] is None
        assert function['reserved_concurrency_configured'] is False
        assert function['provisioned_concurrency_configs'] == []

    def test_provisioned_concurrency(self):
        function = parse(Functions._parse_concurrency, {'provisioned_concurrency_configs': [{
            'FunctionArn': 'arn:aws:lambda:eu-west-1:123456789012:function:Test:live',
            'RequestedProvisionedConcurrentExecutions': 4,
            'AllocatedProvisionedConcurrentExecutions': 4,
            'Status': 'READY'}]})

        assert function['provisioned_concurrency_configs'][0]['requested'] == 4
        assert function['provisioned_concurrency_configs'][0]['status'] == 'READY'


class TestAWSLambdaFunctionFailureHandling(unittest.TestCase):

    def test_dead_letter_queue(self):
        function = parse(Functions._parse_failure_handling, {
            'DeadLetterConfig': {'TargetArn': 'arn:aws:sqs:eu-west-1:123456789012:Test-dlq'}})

        assert function['async_failures_captured'] is True
        assert function['dead_letter_target_arn'].endswith('Test-dlq')

    def test_on_failure_destination(self):
        # The newer destination replaces the dead letter queue, so it counts on its own
        function = parse(Functions._parse_failure_handling, {'event_invoke_configs': [{
            'FunctionArn': 'arn:aws:lambda:eu-west-1:123456789012:function:Test',
            'MaximumRetryAttempts': 1,
            'DestinationConfig': {
                'OnFailure': {'Destination': 'arn:aws:sqs:eu-west-1:123456789012:Test-failures'}}}]})

        assert function['async_failures_captured'] is True
        assert function['on_failure_destinations'] == ['arn:aws:sqs:eu-west-1:123456789012:Test-failures']
        assert function['event_invoke_configs']['Test']['maximum_retry_attempts'] == 1

    def test_invocation_config_keeping_only_successes(self):
        # A configuration exists, but a failed event still has nowhere to go
        function = parse(Functions._parse_failure_handling, {'event_invoke_configs': [{
            'FunctionArn': 'arn:aws:lambda:eu-west-1:123456789012:function:Test',
            'DestinationConfig': {
                'OnSuccess': {'Destination': 'arn:aws:sqs:eu-west-1:123456789012:Test-done'}}}]})

        assert function['async_failures_captured'] is False
        assert function['on_failure_destinations'] == []

    def test_failures_dropped(self):
        function = parse(Functions._parse_failure_handling, {})

        assert function['async_failures_captured'] is False
        assert function['dead_letter_target_arn'] is None


class TestAWSLambdaFunctionRuntimeManagement(unittest.TestCase):

    def test_runtime_updates_applied_by_aws(self):
        function = parse(Functions._parse_runtime_management, {
            'runtime_management_config': {'UpdateRuntimeOn': 'Auto'}})

        assert function['runtime_updates_automatic'] is True
        assert function['runtime_update_mode'] == 'Auto'

    def test_runtime_pinned_to_a_version(self):
        function = parse(Functions._parse_runtime_management, {'runtime_management_config': {
            'UpdateRuntimeOn': 'Manual',
            'RuntimeVersionArn': 'arn:aws:lambda:eu-west-1::runtime:0123456789abcdef'}})

        assert function['runtime_updates_automatic'] is False
        assert function['runtime_update_mode'] == 'Manual'

    def test_runtime_updated_on_the_next_deployment(self):
        function = parse(Functions._parse_runtime_management, {
            'runtime_management_config': {'UpdateRuntimeOn': 'FunctionUpdate'}})

        assert function['runtime_updates_automatic'] is False

    def test_configuration_that_could_not_be_read(self):
        # Auto is the default, and a container image function has no managed runtime at all, so an
        # absent configuration is not reported as a pin
        function = parse(Functions._parse_runtime_management, {})

        assert function['runtime_updates_automatic'] is True
        assert function['runtime_update_mode'] is None


class TestAWSLambdaFunctionLayers(unittest.TestCase):

    @staticmethod
    def _parse_layers(raw_function):
        function = {}
        Functions._parse_layers(raw_function, function, Facade.owner_id)
        return function

    def test_layer_owned_by_the_account(self):
        function = self._parse_layers({'Layers': [{
            'Arn': 'arn:aws:lambda:eu-west-1:123456789012:layer:internal-utils:3',
            'CodeSize': 12903}]})

        assert function['uses_external_layer'] is False
        assert function['external_layers'] == []
        assert function['layers'][0]['account_id'] == '123456789012'

    def test_layer_owned_by_another_account(self):
        function = self._parse_layers({'Layers': [{
            'Arn': 'arn:aws:lambda:eu-west-1:017000801446:layer:AWSLambdaPowertoolsPythonV2:60'}]})

        assert function['uses_external_layer'] is True
        assert len(function['external_layers']) == 1

    def test_function_without_layers(self):
        function = self._parse_layers({})

        assert function['layers'] == []
        assert function['uses_external_layer'] is False


class TestAWSLambdaFunctionEnvironment(unittest.TestCase):

    def test_variables_encrypted_with_a_customer_managed_key(self):
        function = parse(Functions._parse_environment_encryption,
                         {'KMSKeyArn': 'arn:aws:kms:eu-west-1:123456789012:key/0123'},
                         env_variables={'TOKEN': 'value'})

        assert function['environment_encrypted_with_cmk'] is True
        assert function['has_env_variables'] is True

    def test_variables_left_to_the_aws_managed_key(self):
        function = parse(Functions._parse_environment_encryption, {},
                         env_variables={'TOKEN': 'value'})

        assert function['environment_encrypted_with_cmk'] is False
        assert function['has_env_variables'] is True

    def test_function_without_variables(self):
        # There is nothing to encrypt, so the missing key decides nothing
        function = parse(Functions._parse_environment_encryption, {}, env_variables=[])

        assert function['environment_encrypted_with_cmk'] is False
        assert function['has_env_variables'] is False


class TestAWSLambdaFunctionTracing(unittest.TestCase):

    def test_active_tracing(self):
        function = parse(Functions._parse_tracing, {'TracingConfig': {'Mode': 'Active'}})

        assert function['tracing_enabled'] is True
        assert function['tracing_mode'] == 'Active'

    def test_tracing_left_to_the_caller(self):
        function = parse(Functions._parse_tracing, {'TracingConfig': {'Mode': 'PassThrough'}})

        assert function['tracing_enabled'] is False
        assert function['tracing_mode'] == 'PassThrough'


class TestAWSLambdaLayers(unittest.TestCase):

    @staticmethod
    def _parse_layer(raw_layer):
        return Layers(Facade(), 'eu-west-1')._parse_layer(raw_layer)

    def test_layer_with_a_shared_version(self):
        name, layer = self._parse_layer({
            'LayerName': 'internal-utils',
            'LayerArn': 'arn:aws:lambda:eu-west-1:123456789012:layer:internal-utils',
            'LatestMatchingVersion': {'Version': 2},
            'versions': [
                {'Version': 1,
                 'LayerVersionArn': 'arn:aws:lambda:eu-west-1:123456789012:layer:internal-utils:1',
                 'CompatibleRuntimes': ['python3.12'],
                 'policy': {'Statement': [{'Effect': 'Allow', 'Principal': '*'}]}},
                {'Version': 2,
                 'LayerVersionArn': 'arn:aws:lambda:eu-west-1:123456789012:layer:internal-utils:2'}]})

        assert layer['latest_version'] == 2
        assert layer['versions_count'] == 2
        # Versions are keyed by their number so a rule can reach one statement of one version
        assert 'policy' in layer['versions']['1']
        assert layer['versions']['1']['compatible_runtimes'] == ['python3.12']
        # A version nobody was granted access to carries no policy at all
        assert 'policy' not in layer['versions']['2']
        assert name == get_non_provider_id('internal-utils')

    def test_layer_whose_versions_could_not_be_listed(self):
        _, layer = self._parse_layer({
            'LayerName': 'internal-utils',
            'LayerArn': 'arn:aws:lambda:eu-west-1:123456789012:layer:internal-utils'})

        assert layer['versions'] == {}
        assert layer['versions_count'] == 0
        assert layer['latest_version'] is None
