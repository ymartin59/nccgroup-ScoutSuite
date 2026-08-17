from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources


class RegistrySettings(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        # Each region holds a single private registry whose settings apply to all of its repositories.
        # As ScoutSuite expects every setting to belong to a resource, they are held by a made up one,
        # the way EC2 regional settings are.
        raw_registry = await self.facade.ecr.get_registry(self.region)
        self[0] = self._parse_registry(raw_registry)

    def _parse_registry(self, raw_registry):
        registry = {}
        registry['id'] = raw_registry.get('registryId')
        registry['name'] = self.region
        registry['region'] = self.region

        self._parse_scanning(raw_registry, registry)
        self._parse_replication(raw_registry, registry)

        # A registry policy is only there to let other accounts replicate from this registry or pull
        # through its cache, so most registries have none
        policy = raw_registry.get('policy')
        if policy:
            registry['policy'] = policy

        registry['pull_through_cache_rules'] = raw_registry.get('pullThroughCacheRules', [])
        registry['pull_through_cache_rules_count'] = len(registry['pull_through_cache_rules'])

        return registry

    @staticmethod
    def _parse_scanning(raw_registry, registry):
        # BASIC scanning only looks at operating system packages of the images it is asked about, while
        # ENHANCED hands the repositories to Amazon Inspector, which also covers programming language
        # packages and keeps findings up to date as new vulnerabilities are published
        scanning_configuration = raw_registry.get('scanningConfiguration') or {}
        registry['scan_type'] = scanning_configuration.get('scanType')
        registry['scanning_rules'] = scanning_configuration.get('rules', [])

    @staticmethod
    def _parse_replication(raw_registry, registry):
        replication_configuration = raw_registry.get('replicationConfiguration') or {}
        rules = replication_configuration.get('rules', [])
        registry['replication_rules'] = rules
        registry['replication_rules_count'] = len(rules)

        # Destinations tell where copies of the images end up, and which of them leave the account
        destinations = [destination for rule in rules for destination in rule.get('destinations', [])]
        registry['replication_destinations'] = destinations
        registry['cross_account_replication_destinations'] = \
            [destination for destination in destinations
             if destination.get('registryId') and destination.get('registryId') != registry['id']]
