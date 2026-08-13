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

        deprecation_date = self._get_deprecation_date(function_dict['runtime'])
        function_dict['runtime_deprecated'] = not None is deprecation_date and datetime.date.today() >= deprecation_date
        function_dict['date_runtime_deprecated'] = str(deprecation_date)

        await self._add_role_information(function_dict, raw_function.get('Role'))
        await self._add_access_policy_information(function_dict)
        await self._add_env_variables(function_dict)

        return get_non_provider_id(function_dict['name']), function_dict

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
