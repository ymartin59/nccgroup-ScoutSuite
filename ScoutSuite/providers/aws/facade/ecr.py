import json

from asyncio import Lock

from ScoutSuite.core.console import print_exception, print_warning
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import get_and_set_concurrently, run_concurrently


class ECRFacade(AWSBaseFacade):
    # BatchGetRepositoryScanningConfiguration accepts at most 100 repository names per call
    _SCANNING_CONFIGURATION_BATCH_SIZE = 100

    regional_repositories_cache_locks = {}
    repositories_cache = {}

    async def get_repositories(self, region: str):
        await self._cache_repositories(region)
        return self.repositories_cache[region]

    async def _cache_repositories(self, region: str):
        """Describe every repository of the region once, as both the repositories and the images
        resources walk the same list."""

        async with self.regional_repositories_cache_locks.setdefault(region, Lock()):
            if region in self.repositories_cache:
                return

            try:
                repositories = await AWSFacadeUtils.get_all_pages(
                    'ecr', region, self.session, 'describe_repositories', 'repositories')
            except Exception as e:
                print_exception('Failed to describe ECR repositories: {}'.format(e))
                repositories = []

            await self._get_and_set_scanning_configurations(repositories, region)
            await get_and_set_concurrently(
                [self._get_and_set_repository_policy,
                 self._get_and_set_lifecycle_policy,
                 self._get_and_set_repository_tags],
                repositories,
                region=region)

            self.repositories_cache[region] = repositories

    async def _get_and_set_scanning_configurations(self, repositories: [], region: str):
        """Attach to each repository the scanning configuration it ends up with. A repository whose own
        imageScanningConfiguration has no scan on push is still scanned when a registry-wide rule covers
        it, and only this call reports the resulting frequency."""

        client = AWSFacadeUtils.get_client('ecr', self.session, region)

        # Registry-wide scanning was introduced in October 2021, keep working with older botocore versions
        if not hasattr(client, 'batch_get_repository_scanning_configuration'):
            print_warning('Failed to get ECR repository scanning configurations: the installed botocore version '
                          'does not support BatchGetRepositoryScanningConfiguration')
            return

        repository_names = [repository['repositoryName'] for repository in repositories]
        configurations = {}
        for index in range(0, len(repository_names), self._SCANNING_CONFIGURATION_BATCH_SIZE):
            batch = repository_names[index:index + self._SCANNING_CONFIGURATION_BATCH_SIZE]
            try:
                response = await run_concurrently(
                    lambda batch=batch: client.batch_get_repository_scanning_configuration(repositoryNames=batch))
            except Exception as e:
                print_exception('Failed to get ECR repository scanning configurations: {}'.format(e))
                continue

            for configuration in response.get('scanningConfigurations', []):
                configurations[configuration.get('repositoryName')] = configuration

        for repository in repositories:
            repository['scanningConfiguration'] = configurations.get(repository['repositoryName'])

    async def _get_and_set_repository_policy(self, repository: {}, region: str):
        client = AWSFacadeUtils.get_client('ecr', self.session, region)

        try:
            policy = await run_concurrently(
                lambda: client.get_repository_policy(repositoryName=repository['repositoryName'])['policyText'])
        except Exception as e:
            # Having no resource-based policy at all is the common case, not an error
            if 'RepositoryPolicyNotFoundException' in str(e):
                return
            elif 'RepositoryNotFoundException' in str(e):
                print_warning('Failed to get ECR repository policy: {}'.format(e))
            else:
                print_exception('Failed to get ECR repository policy: {}'.format(e))
            return

        repository['policy'] = self._load_policy(policy, 'repository policy for {}'.format(
            repository['repositoryName']))

    async def _get_and_set_lifecycle_policy(self, repository: {}, region: str):
        client = AWSFacadeUtils.get_client('ecr', self.session, region)

        try:
            policy = await run_concurrently(
                lambda: client.get_lifecycle_policy(
                    repositoryName=repository['repositoryName'])['lifecyclePolicyText'])
        except Exception as e:
            # A repository is created without any lifecycle policy, so its absence is not an error
            if 'LifecyclePolicyNotFoundException' in str(e):
                return
            elif 'RepositoryNotFoundException' in str(e):
                print_warning('Failed to get ECR lifecycle policy: {}'.format(e))
            else:
                print_exception('Failed to get ECR lifecycle policy: {}'.format(e))
            return

        repository['lifecyclePolicy'] = self._load_policy(policy, 'lifecycle policy for {}'.format(
            repository['repositoryName']))

    async def _get_and_set_repository_tags(self, repository: {}, region: str):
        client = AWSFacadeUtils.get_client('ecr', self.session, region)

        try:
            tags = await run_concurrently(
                lambda: client.list_tags_for_resource(resourceArn=repository['repositoryArn']))
            repository['tags'] = tags.get('tags')
        except Exception as e:
            if 'RepositoryNotFoundException' in str(e):
                print_warning('Failed to list ECR repository tags: {}'.format(e))
            else:
                print_exception('Failed to list ECR repository tags: {}'.format(e))

    async def get_registry(self, region: str):
        """Return the settings of the region's private registry, which hold what is configured once for
        every repository it contains."""

        registry = {}
        await get_and_set_concurrently(
            [self._get_and_set_replication_configuration,
             self._get_and_set_registry_policy,
             self._get_and_set_registry_scanning_configuration,
             self._get_and_set_pull_through_cache_rules],
            [registry],
            region=region)

        return registry

    async def _get_and_set_replication_configuration(self, registry: {}, region: str):
        client = AWSFacadeUtils.get_client('ecr', self.session, region)

        try:
            description = await run_concurrently(lambda: client.describe_registry())
        except Exception as e:
            print_exception('Failed to describe the ECR registry: {}'.format(e))
            return

        registry['registryId'] = description.get('registryId')
        registry['replicationConfiguration'] = description.get('replicationConfiguration')

    async def _get_and_set_registry_policy(self, registry: {}, region: str):
        client = AWSFacadeUtils.get_client('ecr', self.session, region)

        try:
            policy = await run_concurrently(lambda: client.get_registry_policy()['policyText'])
        except Exception as e:
            # A registry has no policy until one is attached, most often for cross-account replication
            if 'RegistryPolicyNotFoundException' in str(e):
                return
            print_exception('Failed to get the ECR registry policy: {}'.format(e))
            return

        registry['policy'] = self._load_policy(policy, 'registry policy in {}'.format(region))

    async def _get_and_set_registry_scanning_configuration(self, registry: {}, region: str):
        client = AWSFacadeUtils.get_client('ecr', self.session, region)

        if not hasattr(client, 'get_registry_scanning_configuration'):
            print_warning('Failed to get the ECR registry scanning configuration: the installed botocore version '
                          'does not support GetRegistryScanningConfiguration')
            return

        try:
            configuration = await run_concurrently(lambda: client.get_registry_scanning_configuration())
        except Exception as e:
            print_exception('Failed to get the ECR registry scanning configuration: {}'.format(e))
            return

        registry['scanningConfiguration'] = configuration.get('scanningConfiguration')

    async def _get_and_set_pull_through_cache_rules(self, registry: {}, region: str):
        client = AWSFacadeUtils.get_client('ecr', self.session, region)

        if not hasattr(client, 'describe_pull_through_cache_rules'):
            print_warning('Failed to describe the ECR pull through cache rules: the installed botocore version '
                          'does not support DescribePullThroughCacheRules')
            return

        # DescribePullThroughCacheRules is not exposed as a paginator by every botocore version,
        # page through it by hand
        rules = []
        next_token = None
        try:
            while True:
                arguments = {'nextToken': next_token} if next_token else {}
                response = await run_concurrently(
                    lambda arguments=arguments: client.describe_pull_through_cache_rules(**arguments))
                rules.extend(response.get('pullThroughCacheRules', []))
                next_token = response.get('nextToken')
                if not next_token:
                    break
        except Exception as e:
            print_exception('Failed to describe the ECR pull through cache rules: {}'.format(e))
            return

        registry['pullThroughCacheRules'] = rules

    async def get_images(self, region: str, repository_name: str):
        try:
            images = await AWSFacadeUtils.get_all_pages(
                'ecr', region, self.session, 'describe_images', 'imageDetails', repositoryName=repository_name)
        except Exception as e:
            print_exception('Failed to describe ECR images in repository {}: {}'.format(repository_name, e))
            return []

        await get_and_set_concurrently([self._get_and_set_image_scan_findings], images, region=region)
        return images

    async def _get_and_set_image_scan_findings(self, image: {}, region: str):
        """Attach the severity counts of the image's last scan. DescribeImages no longer reports them for
        repositories on the current basic scanning, so they have to be read from the findings themselves."""

        client = AWSFacadeUtils.get_client('ecr', self.session, region)

        try:
            # Only the aggregated counts are of interest here, not the findings themselves
            findings = await run_concurrently(
                lambda: client.describe_image_scan_findings(
                    repositoryName=image['repositoryName'],
                    imageId={'imageDigest': image['imageDigest']},
                    maxResults=1))
        except Exception as e:
            # An image that was never scanned, or whose type cannot be scanned at all, has no findings
            if 'ScanNotFoundException' in str(e) or 'UnsupportedImageTypeException' in str(e):
                return
            elif 'ImageNotFoundException' in str(e) or 'RepositoryNotFoundException' in str(e):
                print_warning('Failed to describe ECR image scan findings: {}'.format(e))
            else:
                print_exception('Failed to describe ECR image scan findings: {}'.format(e))
            return

        image['imageScanStatus'] = findings.get('imageScanStatus')
        image['imageScanFindings'] = {
            key: value for key, value in findings.get('imageScanFindings', {}).items()
            if key in ['imageScanCompletedAt', 'vulnerabilitySourceUpdatedAt', 'findingSeverityCounts']
        }

    @staticmethod
    def _load_policy(policy_text: str, description: str):
        try:
            return json.loads(policy_text)
        except ValueError as e:
            print_exception('Failed to parse the ECR {}: {}'.format(description, e))
            return None
