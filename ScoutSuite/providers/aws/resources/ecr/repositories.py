from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.utils import policy_restricts_to_vpc_endpoint
from ScoutSuite.providers.utils import get_non_provider_id

# Scan frequencies under which every image pushed to the repository ends up scanned, as opposed to
# MANUAL, which leaves scanning to whoever remembers to ask for it
AUTOMATIC_SCAN_FREQUENCIES = ['SCAN_ON_PUSH', 'CONTINUOUS_SCAN']


class Repositories(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        raw_repositories = await self.facade.ecr.get_repositories(self.region)
        for raw_repository in raw_repositories:
            name, resource = self._parse_repository(raw_repository)
            self[name] = resource

    def _parse_repository(self, raw_repository):
        repository = {}
        repository['name'] = raw_repository['repositoryName']
        repository['id'] = get_non_provider_id(raw_repository['repositoryName'])
        repository['arn'] = raw_repository['repositoryArn']
        repository['registry_id'] = raw_repository.get('registryId')
        repository['uri'] = raw_repository.get('repositoryUri')
        repository['region'] = self.region
        created_at = raw_repository.get('createdAt')
        repository['created_at'] = created_at.strftime('%Y-%m-%d %H:%M:%S') if created_at else None
        repository['tags'] = raw_repository.get('tags')

        self._parse_tag_mutability(raw_repository, repository)
        self._parse_encryption(raw_repository, repository)
        self._parse_scanning(raw_repository, repository)
        self._parse_policies(raw_repository, repository)

        return repository['id'], repository

    @staticmethod
    def _parse_tag_mutability(raw_repository, repository):
        # Besides IMMUTABLE and MUTABLE, a repository may be set to IMMUTABLE_WITH_EXCLUSION or
        # MUTABLE_WITH_EXCLUSION, which carry wildcard filters flipping the setting back for the tags
        # they match. Only a plain IMMUTABLE holds for every tag of the repository.
        mutability = raw_repository.get('imageTagMutability')
        repository['image_tag_mutability'] = mutability
        repository['image_tag_mutability_exclusion_filters'] = \
            raw_repository.get('imageTagMutabilityExclusionFilters')
        repository['image_tags_immutable'] = mutability == 'IMMUTABLE'

    @staticmethod
    def _parse_encryption(raw_repository, repository):
        # Images are always encrypted at rest, with an S3 managed key when the repository was created
        # with AES256 and with a KMS key otherwise. KMS_DSSE only differs in applying the cipher twice.
        encryption = raw_repository.get('encryptionConfiguration', {})
        repository['encryption_type'] = encryption.get('encryptionType')
        repository['kms_key'] = encryption.get('kmsKey')
        repository['encrypted_with_kms_key'] = encryption.get('encryptionType') in ['KMS', 'KMS_DSSE']

    @staticmethod
    def _parse_scanning(raw_repository, repository):
        # The repository's own configuration only carries basic scan on push. Enhanced scanning is turned
        # on for the whole registry and matches repositories with filters, so the frequency reported by
        # the scanning configuration is the only attribute that tells whether images do get scanned.
        repository['scan_on_push'] = raw_repository.get('imageScanningConfiguration', {}).get('scanOnPush', False)

        scanning_configuration = raw_repository.get('scanningConfiguration') or {}
        repository['scan_frequency'] = scanning_configuration.get('scanFrequency')
        repository['applied_scan_filters'] = scanning_configuration.get('appliedScanFilters')
        repository['scanning_configured'] = \
            repository['scan_frequency'] in AUTOMATIC_SCAN_FREQUENCIES if repository['scan_frequency'] \
            else repository['scan_on_push']

    @staticmethod
    def _parse_policies(raw_repository, repository):
        # Only set the attributes when a policy exists, so that rules can tell a repository with no
        # policy apart from one whose policy has no statement
        policy = raw_repository.get('policy')
        if policy:
            repository['policy'] = policy
        lifecycle_policy = raw_repository.get('lifecyclePolicy')
        if lifecycle_policy:
            repository['lifecycle_policy'] = lifecycle_policy

        repository['lifecycle_policy_configured'] = bool(lifecycle_policy)
        repository['policy_restricts_to_vpc_endpoint'] = \
            policy_restricts_to_vpc_endpoint(policy) if policy else False
