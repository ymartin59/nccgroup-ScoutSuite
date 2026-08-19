import datetime
from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id
from ScoutSuite.core.console import print_exception


class Functions(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region
        self._deprecationWarningShown = False

    async def fetch_all(self):
        raw_functions = await self.facade.awslambda.get_functions(self.region)
        for raw_function in raw_functions:
            name, resource = await self._parse_function(raw_function)
            self[name] = resource

    async def _parse_function(self, raw_function):

        function_dict = {}
        function_dict['name'] = raw_function.get('FunctionName')
        function_dict['arn'] = raw_function.get('FunctionArn')
        function_dict['runtime'] = raw_function.get('Runtime')
        function_dict['handler'] = raw_function.get('Handler')
        function_dict['code_size'] = raw_function.get('CodeSize')
        function_dict['description'] = raw_function.get('Description')
        function_dict['timeout'] = raw_function.get('Timeout')
        function_dict['memory_size'] = raw_function.get('MemorySize')
        function_dict['last_modified'] = raw_function.get('LastModified')
        function_dict['code_sha256'] = raw_function.get('CodeSha256')
        function_dict['version'] = raw_function.get('Version')
        function_dict['tracing_config'] = raw_function.get('TracingConfig')
        function_dict['revision_id'] = raw_function.get('RevisionId')
        function_dict['region'] = self.region
        function_dict['state'] = raw_function.get('State')
        # A container image function brings its own runtime and its own build chain, so several of
        # the controls below simply do not exist for it
        function_dict['package_type'] = raw_function.get('PackageType', 'Zip')
        function_dict['architectures'] = raw_function.get('Architectures') or []
        function_dict['ephemeral_storage'] = (raw_function.get('EphemeralStorage') or {}).get('Size')
        function_dict['log_group'] = (raw_function.get('LoggingConfig') or {}).get('LogGroup')
        function_dict['snap_start'] = raw_function.get('SnapStart')

        deprecation_date = self._get_deprecation_date(function_dict['runtime'])
        function_dict['runtime_deprecated'] = not None is deprecation_date and datetime.date.today() >= deprecation_date
        function_dict['date_runtime_deprecated'] = str(deprecation_date)

        self._parse_tracing(raw_function, function_dict)
        self._parse_vpc_config(raw_function, function_dict)
        self._parse_url_configs(raw_function, function_dict)
        self._parse_code_signing(raw_function, function_dict)
        self._parse_concurrency(raw_function, function_dict)
        self._parse_failure_handling(raw_function, function_dict)
        self._parse_runtime_management(raw_function, function_dict)
        self._parse_layers(raw_function, function_dict, self.facade.owner_id)

        await self._add_role_information(function_dict, raw_function.get('Role'))
        await self._add_access_policy_information(function_dict)
        await self._add_env_variables(function_dict)
        self._parse_environment_encryption(raw_function, function_dict)

        return get_non_provider_id(function_dict['name']), function_dict

    @staticmethod
    def _parse_tracing(raw_function, function_dict):
        mode = (raw_function.get('TracingConfig') or {}).get('Mode')
        function_dict['tracing_mode'] = mode
        function_dict['tracing_enabled'] = mode == 'Active'

    @staticmethod
    def _parse_vpc_config(raw_function, function_dict):
        """Which VPC, subnets and security groups the function's network interfaces live in. Lambda
        reports an empty configuration for a function that is not attached to a VPC, and only fills
        in the VPC id once there are subnets, so the subnets are what says whether it is attached."""

        vpc_config = raw_function.get('VpcConfig') or {}
        subnet_ids = vpc_config.get('SubnetIds') or []

        function_dict['in_vpc'] = bool(subnet_ids)
        function_dict['vpc_config'] = {
            'vpc_id': vpc_config.get('VpcId'),
            'subnet_ids': subnet_ids,
            'security_group_ids': vpc_config.get('SecurityGroupIds') or [],
            'ipv6_allowed_for_dual_stack': vpc_config.get('Ipv6AllowedForDualStack', False),
        }

    @staticmethod
    def _parse_url_configs(raw_function, function_dict):
        """The function URLs, keyed by the version or alias they invoke. AuthType NONE means Lambda
        runs the function for anyone who knows the URL, and the CORS settings decide which web pages
        a browser will let call it."""

        url_configs = {}
        unauthenticated = False
        cors_allows_all_origins = False

        for raw_config in raw_function.get('url_configs') or []:
            qualifier = raw_config.get('Qualifier') or '$LATEST'
            cors = raw_config.get('Cors') or {}
            allow_origins = cors.get('AllowOrigins') or []

            url_configs[qualifier] = {
                'qualifier': qualifier,
                'url': raw_config.get('FunctionUrl'),
                'auth_type': raw_config.get('AuthType'),
                'invoke_mode': raw_config.get('InvokeMode', 'BUFFERED'),
                'creation_time': raw_config.get('CreationTime'),
                'cors_allow_origins': allow_origins,
                'cors_allow_credentials': cors.get('AllowCredentials', False),
                'cors_allow_headers': cors.get('AllowHeaders') or [],
                'cors_allow_methods': cors.get('AllowMethods') or [],
            }

            unauthenticated |= raw_config.get('AuthType') == 'NONE'
            cors_allows_all_origins |= '*' in allow_origins

        function_dict['url_configs'] = url_configs
        function_dict['url_configured'] = bool(url_configs)
        function_dict['url_unauthenticated'] = unauthenticated
        function_dict['url_cors_allows_all_origins'] = cors_allows_all_origins

    @staticmethod
    def _parse_code_signing(raw_function, function_dict):
        """The code signing configuration attached to the function, if any. Enforce rejects a
        deployment package that none of the trusted signing profiles signed, Warn only writes the
        failure to CloudTrail and deploys it anyway."""

        config = raw_function.get('code_signing_config') or {}
        untrusted_artifact_policy = (config.get('CodeSigningPolicies') or {}).get('UntrustedArtifactOnDeployment')

        function_dict['code_signing_enabled'] = bool(config)
        function_dict['code_signing_config_arn'] = config.get('CodeSigningConfigArn')
        function_dict['code_signing_untrusted_artifact_policy'] = untrusted_artifact_policy
        function_dict['code_signing_enforced'] = untrusted_artifact_policy == 'Enforce'
        function_dict['code_signing_allowed_publishers'] = \
            (config.get('AllowedPublishers') or {}).get('SigningProfileVersionArns') or []
        # Set by Lambda on the deployed version, whether or not a configuration is attached now
        function_dict['signing_profile_version_arn'] = raw_function.get('SigningProfileVersionArn')
        function_dict['signing_job_arn'] = raw_function.get('SigningJobArn')

    @staticmethod
    def _parse_concurrency(raw_function, function_dict):
        reserved = raw_function.get('ReservedConcurrentExecutions')
        provisioned = raw_function.get('provisioned_concurrency_configs') or []

        function_dict['reserved_concurrency'] = reserved
        function_dict['reserved_concurrency_configured'] = reserved is not None
        function_dict['provisioned_concurrency_configs'] = [
            {
                'arn': config.get('FunctionArn'),
                'requested': config.get('RequestedProvisionedConcurrentExecutions'),
                'allocated': config.get('AllocatedProvisionedConcurrentExecutions'),
                'status': config.get('Status'),
            }
            for config in provisioned
        ]

    @staticmethod
    def _parse_failure_handling(raw_function, function_dict):
        """What becomes of an asynchronous invocation Lambda could not run. Both the dead letter
        queue and the newer on-failure destination keep the event, so a function needs one of the
        two, not both."""

        dead_letter_target_arn = (raw_function.get('DeadLetterConfig') or {}).get('TargetArn')
        event_invoke_configs = {}
        on_failure_destinations = []

        for config in raw_function.get('event_invoke_configs') or []:
            qualifier = (config.get('FunctionArn') or '').split(':')[-1]
            destination_config = config.get('DestinationConfig') or {}
            on_failure = (destination_config.get('OnFailure') or {}).get('Destination')

            event_invoke_configs[qualifier] = {
                'qualifier': qualifier,
                'maximum_retry_attempts': config.get('MaximumRetryAttempts'),
                'maximum_event_age_in_seconds': config.get('MaximumEventAgeInSeconds'),
                'on_failure_destination': on_failure,
                'on_success_destination': (destination_config.get('OnSuccess') or {}).get('Destination'),
            }

            if on_failure:
                on_failure_destinations.append(on_failure)

        function_dict['dead_letter_target_arn'] = dead_letter_target_arn
        function_dict['event_invoke_configs'] = event_invoke_configs
        function_dict['on_failure_destinations'] = on_failure_destinations
        function_dict['async_failures_captured'] = bool(dead_letter_target_arn or on_failure_destinations)

    @staticmethod
    def _parse_runtime_management(raw_function, function_dict):
        """Auto lets AWS move the function onto a patched runtime version by itself, the other two
        modes leave that to whoever deploys the function. Auto is the default, and a function whose
        configuration could not be read is not reported as pinned."""

        config = raw_function.get('runtime_management_config') or {}
        update_runtime_on = config.get('UpdateRuntimeOn')

        function_dict['runtime_update_mode'] = update_runtime_on
        function_dict['runtime_updates_automatic'] = update_runtime_on in (None, 'Auto')
        function_dict['runtime_version_arn'] = config.get('RuntimeVersionArn')

    @staticmethod
    def _parse_layers(raw_function, function_dict, owner_id):
        """The layers the function unpacks into its execution environment, and which account owns
        each one. A layer version is immutable, but a layer owned elsewhere is code running under the
        function's role that this account did not build and cannot inspect."""

        layers = []
        external_layers = []

        for raw_layer in raw_function.get('Layers') or []:
            arn = raw_layer.get('Arn') or ''
            # arn:<partition>:lambda:<region>:<account id>:layer:<name>:<version>
            arn_fields = arn.split(':')
            account_id = arn_fields[4] if len(arn_fields) > 4 else None

            layers.append({
                'arn': arn,
                'account_id': account_id,
                'code_size': raw_layer.get('CodeSize'),
                'signing_profile_version_arn': raw_layer.get('SigningProfileVersionArn'),
                'signing_job_arn': raw_layer.get('SigningJobArn'),
            })

            if account_id and owner_id and account_id != owner_id:
                external_layers.append(arn)

        function_dict['layers'] = layers
        function_dict['external_layers'] = external_layers
        function_dict['uses_external_layer'] = bool(external_layers)

    @staticmethod
    def _parse_environment_encryption(raw_function, function_dict):
        """Environment variables are always encrypted at rest, with a key of the account's choosing
        or with the AWS managed one Lambda uses by default."""

        kms_key_arn = raw_function.get('KMSKeyArn')

        function_dict['kms_key_arn'] = kms_key_arn
        function_dict['environment_encrypted_with_cmk'] = bool(kms_key_arn)
        function_dict['has_env_variables'] = bool(function_dict.get('env_variables'))

    async def _add_role_information(self, function_dict, role_id):
        # Make it easier to build rules based on policies attached to execution roles
        function_dict['role_arn'] = role_id
        role_name = role_id.split("/")[-1]
        function_dict['execution_role'] = await self.facade.awslambda.get_role_with_managed_policies(role_name)
        if function_dict.get('execution_role'):
            statements = []
            for policy in function_dict['execution_role'].get('policies'):
                if 'Document' in policy and 'Statement' in policy['Document']:
                    statements += policy['Document']['Statement']
            function_dict['execution_role']['policy_statements'] = statements

    async def _add_access_policy_information(self, function_dict):
        access_policy = await self.facade.awslambda.get_access_policy(function_dict['name'], self.region)

        if access_policy:
            function_dict['access_policy'] = access_policy
        else:
            # If there's no policy, set an empty one
            function_dict['access_policy'] = {'Version': '2012-10-17',
                                              'Id': 'default',
                                              'Statement': []}

    async def _add_env_variables(self, function_dict):
        env_variables = await self.facade.awslambda.get_env_variables(function_dict['name'], self.region)
        function_dict["env_variables"] = env_variables
        # The following properties are for easier rule creation
        if env_variables:
            function_dict["env_variable_names"] = list(env_variables.keys())
            function_dict["env_variable_values"] = list(env_variables.values())
        else:
            function_dict["env_variable_names"] = []
            function_dict["env_variable_values"] = []

    def _get_deprecation_date(self, runtime):
        # As of August 2026, the Lambda API does not have a way to determine whether a Lambda
        # runtime is deprecated; that information is only available in AWS documentation.
        # Consequently, the table here will need to be updated from time to time.
        # Upcoming deprecation dates: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html#runtimes-supported
        # Past deprecation dates: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html#runtimes-deprecated

        # Table of runtime identifier : deprecation date
        # If a particular runtime identifier does not appear in the table, then no deprecation
        # date for the runtime has been announced. This is currently the case for the
        # Amazon Linux 2023 Java runtimes: java8.al2023, java11.al2023 and java17.al2023.
        last_updated = datetime.date(2026, 8, 13)
        deprecations = {
            'python3.14': datetime.date(2029, 6, 30), # Jun 30, 2029
            'python3.13': datetime.date(2029, 6, 30), # Jun 30, 2029
            'java25': datetime.date(2029, 6, 30), # Jun 30, 2029
            'java21': datetime.date(2029, 6, 30), # Jun 30, 2029
            'provided.al2023': datetime.date(2029, 6, 30), # Jun 30, 2029
            'ruby4.0': datetime.date(2029, 3, 31), # Mar 31, 2029
            'dotnet10': datetime.date(2028, 11, 14), # Nov 14, 2028
            'python3.12': datetime.date(2028, 10, 31), # Oct 31, 2028
            'nodejs24.x': datetime.date(2028, 4, 30), # Apr 30, 2028
            'ruby3.4': datetime.date(2028, 3, 31), # Mar 31, 2028
            'python3.11': datetime.date(2027, 6, 30), # Jun 30, 2027
            'java17': datetime.date(2027, 6, 30), # Jun 30, 2027
            'java11': datetime.date(2027, 6, 30), # Jun 30, 2027
            'java8.al2': datetime.date(2027, 6, 30), # Jun 30, 2027
            'nodejs22.x': datetime.date(2027, 4, 30), # Apr 30, 2027
            'ruby3.3': datetime.date(2027, 3, 31), # Mar 31, 2027
            'dotnet9': datetime.date(2026, 11, 10), # Nov 10, 2026
            'dotnet8': datetime.date(2026, 11, 10), # Nov 10, 2026
            'python3.10': datetime.date(2026, 10, 31), # Oct 31, 2026
            'provided.al2': datetime.date(2026, 7, 31), # Jul 31, 2026
            'nodejs20.x': datetime.date(2026, 4, 30), # Apr 30, 2026
            'ruby3.2': datetime.date(2026, 3, 31), # Mar 31, 2026
            'python3.9': datetime.date(2025, 12, 15), # Dec 15, 2025
            'nodejs18.x': datetime.date(2025, 9, 1), # Sep 1, 2025
            'dotnet6': datetime.date(2024, 12, 20), # Dec 20, 2024
            'python3.8': datetime.date(2024, 10, 14), # Oct 14, 2024
            'nodejs16.x': datetime.date(2024, 6, 12), # Jun 12, 2024
            'dotnet7': datetime.date(2024, 5, 14), # May 14, 2024
            'java8': datetime.date(2024, 1, 8), # Jan 8, 2024
            'go1.x': datetime.date(2024, 1, 8), # Jan 8, 2024
            'provided': datetime.date(2024, 1, 8), # Jan 8, 2024
            'ruby2.7': datetime.date(2023, 12, 7), # Dec 7, 2023
            'nodejs14.x': datetime.date(2023, 12, 4), # Dec 4, 2023
            'python3.7': datetime.date(2023, 12, 4), # Dec 4, 2023
            'dotnetcore3.1': datetime.date(2023, 4, 3), # Apr 3, 2023
            'nodejs12.x': datetime.date(2023, 3, 31), # Mar 31, 2023
            'python3.6': datetime.date(2022, 7, 18), # Jul 18, 2022
            'dotnet5.0': datetime.date(2022, 5, 10), # May 10, 2022
            'dotnetcore2.1': datetime.date(2022, 1, 5), # Jan 5, 2022
            'nodejs10.x': datetime.date(2021, 7, 30), # Jul 30, 2021
            'ruby2.5': datetime.date(2021, 7, 30), # Jul 30, 2021
            'python2.7': datetime.date(2021, 7, 15), # Jul 15, 2021
            'nodejs8.10': datetime.date(2020, 3, 6), # Mar 6, 2020
            'nodejs4.3': datetime.date(2020, 3, 5), # Mar 5, 2020
            'nodejs4.3-edge': datetime.date(2020, 3, 5), # Mar 5, 2020
            'nodejs6.10': datetime.date(2019, 8, 12), # Aug 12, 2019
            'dotnetcore1.0': datetime.date(2019, 6, 27), # Jun 27, 2019
            'dotnetcore2.0': datetime.date(2019, 5, 30), # May 30, 2019
            'nodejs': datetime.date(2016, 8, 30), # Aug 30, 2016
        }

        # Warn if the table hasn't been updated
        if datetime.timedelta(days=180) < datetime.date.today() - last_updated \
           and not self._deprecationWarningShown:
            print_exception('Deprecation table has not been updated in over 180 days. Please ' 
                'update ScoutSuite to the latest release or update the deprecations table in '
                'ScoutSuite/providers/aws/resources/awslambda/functions.py')
            self._deprecationWarningShown = True

        if not runtime in deprecations:
            return None
        return deprecations[runtime]
