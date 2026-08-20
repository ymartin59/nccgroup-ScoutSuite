from asyncio import Lock
from typing import Dict, List, Optional

from ScoutSuite.core.console import print_exception, print_info
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently, get_and_set_concurrently, map_concurrently

# A training job record is kept for ever, so an account that trains regularly accumulates them
# without bound, while only DescribeTrainingJob carries the isolation and encryption settings a rule
# is about. The jobs that describe how the account trains today are the most recent ones, so the
# listing is sorted newest first and cut here rather than turning one scan into tens of thousands of
# calls. What was dropped is reported, so the report never silently claims to have looked at every
# job.
TRAINING_JOB_LIMIT = 200


class SageMakerFacade(AWSBaseFacade):
    _endpoint_config_cache_locks = {}
    _endpoint_config_cache = {}

    async def get_notebook_instances(self, region: str) -> List[Dict]:
        """The notebook instances of a region. ListNotebookInstances reports the name, the instance
        type and the status only, so everything that decides what a notebook may reach and what
        protects its volume comes from DescribeNotebookInstance."""

        summaries = await self._get_all_pages(region, 'list_notebook_instances', 'NotebookInstances')

        return [notebook for notebook in await map_concurrently(
            self._describe_notebook_instance, summaries, region=region) if notebook]

    async def get_domains(self, region: str) -> List[Dict]:
        """The SageMaker Studio domains of a region, each with the user profiles it holds.

        ListDomains does report the network access type, but not the VPC, the keys or the default
        user settings, so each domain is described. The user profiles are listed and described per
        domain, since the execution role a profile overrides the domain default with is what its
        notebooks actually run as."""

        summaries = await self._get_all_pages(region, 'list_domains', 'Domains')

        domains = [domain for domain in await map_concurrently(
            self._describe_domain, summaries, region=region) if domain]

        await get_and_set_concurrently([self._get_and_set_user_profiles], domains, region=region)

        return domains

    async def get_endpoints(self, region: str) -> List[Dict]:
        """The inference endpoints of a region, each with the endpoint configuration it currently
        serves. The endpoint itself only reports the name of that configuration, while the volume
        encryption key, the network isolation and the VPC placement of the instances hosting the
        model are all declared in the configuration."""

        summaries = await self._get_all_pages(region, 'list_endpoints', 'Endpoints')

        endpoints = [endpoint for endpoint in await map_concurrently(
            self._describe_endpoint, summaries, region=region) if endpoint]

        await get_and_set_concurrently([self._get_and_set_endpoint_config], endpoints, region=region)

        return endpoints

    async def get_models(self, region: str) -> List[Dict]:
        summaries = await self._get_all_pages(region, 'list_models', 'Models')

        return [model for model in await map_concurrently(
            self._describe_model, summaries, region=region) if model]

    async def get_training_jobs(self, region: str) -> List[Dict]:
        """The most recent training jobs of a region, newest first, up to TRAINING_JOB_LIMIT.

        The listing itself is stopped at the limit rather than read out in full and cut afterwards: an
        account that trains continuously has tens of thousands of job records, and paging through all
        of them to throw away all but the newest page or two is the same waste in a cheaper call."""

        client = AWSFacadeUtils.get_client('sagemaker', self.session, region)

        summaries, next_token = [], None
        while len(summaries) < TRAINING_JOB_LIMIT:
            args = {'SortBy': 'CreationTime', 'SortOrder': 'Descending',
                    'MaxResults': min(100, TRAINING_JOB_LIMIT - len(summaries))}
            if next_token:
                args['NextToken'] = next_token

            try:
                page = await run_concurrently(lambda arguments=args: client.list_training_jobs(**arguments))
            except Exception as e:
                print_exception(f'Failed to list the SageMaker training jobs of {region}: {e}')
                break

            summaries.extend(page.get('TrainingJobSummaries') or [])
            next_token = page.get('NextToken')
            if not next_token:
                break
        else:
            # The listing was cut, so the report covers how the account trains lately rather than
            # every job it has ever run, and says so
            print_info(f'Only the {TRAINING_JOB_LIMIT} most recent SageMaker training jobs of '
                       f'{region} are collected')

        return [job for job in await map_concurrently(
            self._describe_training_job, summaries, region=region) if job]

    async def _get_and_set_user_profiles(self, domain: Dict, region: str):
        summaries = await self._get_all_pages(
            region, 'list_user_profiles', 'UserProfiles', DomainIdEquals=domain['DomainId'])

        domain['user_profile_details'] = [profile for profile in await map_concurrently(
            self._describe_user_profile, summaries, region=region) if profile]

    async def _get_and_set_endpoint_config(self, endpoint: Dict, region: str):
        config_name = endpoint.get('EndpointConfigName')
        if config_name:
            endpoint['endpoint_config'] = await self._get_endpoint_config(region, config_name)

    async def _get_endpoint_config(self, region: str, config_name: str) -> Optional[Dict]:
        """Read one endpoint configuration. A configuration is immutable and several endpoints can
        serve the same one, so each is only described once."""

        async with self._endpoint_config_cache_locks.setdefault((region, config_name), Lock()):
            if (region, config_name) not in self._endpoint_config_cache:
                self._endpoint_config_cache[(region, config_name)] = await self._describe(
                    region, 'describe_endpoint_config', EndpointConfigName=config_name)

        return self._endpoint_config_cache[(region, config_name)]

    async def _describe_notebook_instance(self, summary: Dict, region: str) -> Optional[Dict]:
        return await self._describe(region, 'describe_notebook_instance',
                                    NotebookInstanceName=summary['NotebookInstanceName'])

    async def _describe_domain(self, summary: Dict, region: str) -> Optional[Dict]:
        return await self._describe(region, 'describe_domain', DomainId=summary['DomainId'])

    async def _describe_user_profile(self, summary: Dict, region: str) -> Optional[Dict]:
        return await self._describe(region, 'describe_user_profile',
                                    DomainId=summary['DomainId'],
                                    UserProfileName=summary['UserProfileName'])

    async def _describe_endpoint(self, summary: Dict, region: str) -> Optional[Dict]:
        return await self._describe(region, 'describe_endpoint', EndpointName=summary['EndpointName'])

    async def _describe_model(self, summary: Dict, region: str) -> Optional[Dict]:
        return await self._describe(region, 'describe_model', ModelName=summary['ModelName'])

    async def _describe_training_job(self, summary: Dict, region: str) -> Optional[Dict]:
        return await self._describe(region, 'describe_training_job',
                                    TrainingJobName=summary['TrainingJobName'])

    async def _describe(self, region: str, method_name: str, **args) -> Optional[Dict]:
        client = AWSFacadeUtils.get_client('sagemaker', self.session, region)
        try:
            method = getattr(client, method_name)
            response = await run_concurrently(lambda: method(**args))
        except Exception as e:
            print_exception(f'Failed to call {method_name} on the SageMaker API '
                            f'for {", ".join(args.values())}: {e}')
            return None

        response.pop('ResponseMetadata', None)
        return response

    async def _get_all_pages(self, region: str, paginator_name: str, entity: str, **args) -> List[Dict]:
        try:
            return await AWSFacadeUtils.get_all_pages(
                'sagemaker', region, self.session, paginator_name, entity, **args)
        except Exception as e:
            print_exception(f'Failed to call {paginator_name} on the SageMaker API: {e}')
            return []
