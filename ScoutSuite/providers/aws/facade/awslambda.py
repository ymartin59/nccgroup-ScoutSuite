import json

from asyncio import Lock
from typing import Dict, List, Optional

from botocore.exceptions import ClientError

from ScoutSuite.core.console import print_exception, print_warning
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently, get_and_set_concurrently


class LambdaFacade(AWSBaseFacade):
    # A code signing configuration is a standalone object that any number of functions point at
    _code_signing_configs_cache_locks = {}
    _code_signing_configs_cache = {}

    async def get_functions(self, region):
        try:
            functions = await AWSFacadeUtils.get_all_pages(
                'lambda', region, self.session, 'list_functions', 'Functions')
        except Exception as e:
            print_exception(f'Failed to get Lambda functions: {e}')
            return []

        # Everything below lives outside the function configuration and has an API of its own
        await get_and_set_concurrently(
            [self._get_and_set_url_configs,
             self._get_and_set_code_signing_config,
             self._get_and_set_concurrency,
             self._get_and_set_event_invoke_configs,
             self._get_and_set_runtime_management_config],
            functions, region=region)

        return functions

    async def get_access_policy(self, function_name, region):
        client = AWSFacadeUtils.get_client('lambda', self.session, region)
        try:
            policy = client.get_policy(FunctionName=function_name)
            if policy is not None and 'Policy' in policy:
                return json.loads(policy['Policy'])
        except Exception as e:
            # If there's no policy, it will return this exception. Hence why we ignore.
            if "ResourceNotFoundException" not in str(e):
                print_exception('Failed to get Lambda access policy: {}'.format(e))
            return None

    async def get_role_with_managed_policies(self, role_name):
        client = AWSFacadeUtils.get_client('iam', self.session)
        try:
            role = client.get_role(RoleName=role_name)['Role']
            managed_policies = client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            for policy in managed_policies:
                policy_version = client.get_policy(PolicyArn=policy['PolicyArn'])
                if 'Policy' in policy_version and 'DefaultVersionId' in policy_version['Policy']:
                    policy_version = policy_version['Policy']['DefaultVersionId']
                    document = client.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=policy_version)
                    if 'PolicyVersion' in document and 'Document' in document['PolicyVersion']:
                        policy['Document'] = document['PolicyVersion']['Document']
            role['policies'] = managed_policies
            return role
        except Exception as e:
            if 'NoSuchEntity' in str(e):
                print_warning(f'Failed to get role from managed policies: {e}')
            else:
                print_exception(f'Failed to get role from managed policies: {e}')
            return None

    async def get_env_variables(self, function_name, region):
        client = AWSFacadeUtils.get_client('lambda', self.session, region)
        try:
            function_configuration = client.get_function_configuration(FunctionName=function_name)
            if "Environment" in function_configuration and "Variables" in function_configuration["Environment"]:
                return function_configuration["Environment"]["Variables"]
        except Exception as e:
            if 'ResourceNotFoundException' in str(e):
                print_warning('Failed to get Lambda function configuration: {}'.format(e))
            else:
                print_exception('Failed to get Lambda function configuration: {}'.format(e))
        return []

    async def get_layers(self, region: str) -> List[Dict]:
        try:
            layers = await AWSFacadeUtils.get_all_pages(
                'lambda', region, self.session, 'list_layers', 'Layers')
        except Exception as e:
            print_exception(f'Failed to list Lambda layers: {e}')
            return []

        await get_and_set_concurrently([self._get_and_set_layer_versions], layers, region=region)

        return layers

    async def _get_and_set_url_configs(self, function: Dict, region: str):
        """A function URL is a dedicated HTTPS endpoint AWS publishes for the function, and it is a
        separate object from the function configuration: whether one exists at all, and whether it
        requires a signature, can only be seen by asking for it."""

        try:
            function['url_configs'] = await AWSFacadeUtils.get_all_pages(
                'lambda', region, self.session, 'list_function_url_configs', 'FunctionUrlConfigs',
                FunctionName=function['FunctionName'])
        except Exception as e:
            print_exception(f'Failed to list Lambda function URL configurations: {e}')

    async def _get_and_set_code_signing_config(self, function: Dict, region: str):
        # Code signing only applies to functions deployed as a .zip archive
        if function.get('PackageType') == 'Image':
            return

        client = AWSFacadeUtils.get_client('lambda', self.session, region)
        try:
            response = await run_concurrently(
                lambda: client.get_function_code_signing_config(FunctionName=function['FunctionName']))
        except Exception as e:
            print_exception(f'Failed to get Lambda function code signing configuration: {e}')
            return

        arn = response.get('CodeSigningConfigArn')
        if not arn:
            return

        config = await self._get_code_signing_config(region, arn)
        if config is not None:
            function['code_signing_config'] = config

    async def _get_code_signing_config(self, region: str, arn: str) -> Optional[Dict]:
        """Read one code signing configuration: the signing profiles it trusts and what Lambda does
        with an artifact none of them signed. Configurations are shared between functions, so each
        one is only fetched once."""

        async with self._code_signing_configs_cache_locks.setdefault(arn, Lock()):
            if arn not in self._code_signing_configs_cache:
                client = AWSFacadeUtils.get_client('lambda', self.session, region)
                try:
                    response = await run_concurrently(
                        lambda: client.get_code_signing_config(CodeSigningConfigArn=arn))
                    config = response.get('CodeSigningConfig')
                except Exception as e:
                    print_exception(f'Failed to get Lambda code signing configuration {arn}: {e}')
                    config = None

                self._code_signing_configs_cache[arn] = config

        return self._code_signing_configs_cache[arn]

    async def _get_and_set_concurrency(self, function: Dict, region: str):
        """Reserved concurrency, the ceiling on how many instances of a function may run at once,
        and the provisioned concurrency kept warm for it. Neither appears in the function
        configuration."""

        client = AWSFacadeUtils.get_client('lambda', self.session, region)
        try:
            response = await run_concurrently(
                lambda: client.get_function_concurrency(FunctionName=function['FunctionName']))
            # The key is absent, rather than null, on a function with no reservation
            if 'ReservedConcurrentExecutions' in response:
                function['ReservedConcurrentExecutions'] = response['ReservedConcurrentExecutions']
        except Exception as e:
            print_exception(f'Failed to get Lambda function concurrency: {e}')

        try:
            function['provisioned_concurrency_configs'] = await AWSFacadeUtils.get_all_pages(
                'lambda', region, self.session, 'list_provisioned_concurrency_configs',
                'ProvisionedConcurrencyConfigs', FunctionName=function['FunctionName'])
        except Exception as e:
            print_exception(f'Failed to list Lambda provisioned concurrency configurations: {e}')

    async def _get_and_set_event_invoke_configs(self, function: Dict, region: str):
        """Where an asynchronous invocation ends up once Lambda gives up retrying it. The on-failure
        destination lives here, the older dead letter queue lives in the function configuration, and
        a function can have either, both or neither."""

        try:
            function['event_invoke_configs'] = await AWSFacadeUtils.get_all_pages(
                'lambda', region, self.session, 'list_function_event_invoke_configs',
                'FunctionEventInvokeConfigs', FunctionName=function['FunctionName'])
        except Exception as e:
            print_exception(f'Failed to list Lambda function event invoke configurations: {e}')

    async def _get_and_set_runtime_management_config(self, function: Dict, region: str):
        """Whether AWS may move the function onto a patched runtime version on its own, or whether
        the account pinned it to the version it was last deployed with."""

        # A container image function brings its own runtime, there is nothing for Lambda to manage
        if function.get('PackageType') == 'Image':
            return

        client = AWSFacadeUtils.get_client('lambda', self.session, region)
        try:
            function['runtime_management_config'] = await run_concurrently(
                lambda: client.get_runtime_management_config(FunctionName=function['FunctionName']))
        except Exception as e:
            print_exception(f'Failed to get Lambda runtime management configuration: {e}')

    async def _get_and_set_layer_versions(self, layer: Dict, region: str):
        try:
            versions = await AWSFacadeUtils.get_all_pages(
                'lambda', region, self.session, 'list_layer_versions', 'LayerVersions',
                LayerName=layer['LayerName'])
        except Exception as e:
            print_exception(f'Failed to list Lambda layer versions: {e}')
            return

        await get_and_set_concurrently(
            [self._get_and_set_layer_version_policy], versions,
            region=region, layer_name=layer['LayerName'])

        layer['versions'] = versions

    async def _get_and_set_layer_version_policy(self, version: Dict, region: str, layer_name: str):
        """A layer version can be handed to another account, to an organization or to everyone,
        through a permission policy that the layer listing does not mention. Every version carries
        its own, so an old version can stay shared long after the current one stopped being."""

        client = AWSFacadeUtils.get_client('lambda', self.session, region)
        try:
            response = await run_concurrently(lambda: client.get_layer_version_policy(
                LayerName=layer_name, VersionNumber=version['Version']))
        except ClientError as e:
            # A version nobody was granted access to answers with ResourceNotFoundException
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                print_exception(f'Failed to get Lambda layer version policy: {e}')
            return
        except Exception as e:
            print_exception(f'Failed to get Lambda layer version policy: {e}')
            return

        if response.get('Policy'):
            try:
                version['policy'] = json.loads(response['Policy'])
            except ValueError as e:
                print_exception(f'Failed to parse Lambda layer version policy: {e}')
