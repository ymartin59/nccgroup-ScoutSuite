from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources


class Configurations(AWSResources):
    """The Amazon MQ configurations of a region, each holding the revisions a broker may be created or
    updated with. A configuration only decides anything while a broker runs one of its revisions, so
    what is reported here is the inventory the account may draw from, not the state of any broker: the
    settings in force are read from the revision each broker currently applies."""

    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw_configuration in await self.facade.mq.get_configurations(self.region):
            id, configuration = self._parse_configuration(raw_configuration)
            self[id] = configuration

    def _parse_configuration(self, raw_configuration):
        latest_revision = raw_configuration.get('LatestRevision') or {}
        created = raw_configuration.get('Created')
        revision_created = latest_revision.get('Created')

        configuration = {}
        configuration['id'] = raw_configuration['Id']
        configuration['name'] = raw_configuration.get('Name')
        configuration['arn'] = raw_configuration.get('Arn')
        configuration['region'] = self.region
        configuration['description'] = raw_configuration.get('Description')
        configuration['engine_type'] = raw_configuration.get('EngineType')
        configuration['engine_version'] = raw_configuration.get('EngineVersion')
        # A configuration is created for one authentication strategy and can only be applied to a
        # broker using that strategy
        configuration['authentication_strategy'] = raw_configuration.get('AuthenticationStrategy')
        configuration['creation_time'] = created.strftime('%Y-%m-%d %H:%M:%S') if created else None
        configuration['latest_revision'] = latest_revision.get('Revision')
        configuration['latest_revision_description'] = latest_revision.get('Description')
        configuration['latest_revision_creation_time'] = \
            revision_created.strftime('%Y-%m-%d %H:%M:%S') if revision_created else None
        configuration['tags'] = raw_configuration.get('Tags') or {}

        return configuration['id'], configuration
