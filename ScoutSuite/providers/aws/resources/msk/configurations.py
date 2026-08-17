from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Configurations(AWSResources):
    """The MSK configurations of a region, each holding the server.properties a cluster may be
    created or updated with. A configuration is only in force while a cluster references it, so what
    is reported here is the inventory the account may draw from, not the state of any cluster."""

    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw_configuration in await self.facade.msk.get_configurations(self.region):
            name, resource = self._parse_configuration(raw_configuration)
            self[name] = resource

    def _parse_configuration(self, raw_configuration):
        latest_revision = raw_configuration.get('LatestRevision') or {}
        creation_time = raw_configuration.get('CreationTime')
        revision_creation_time = latest_revision.get('CreationTime')

        configuration = {}
        configuration['name'] = raw_configuration['Name']
        configuration['arn'] = raw_configuration['Arn']
        configuration['region'] = self.region
        configuration['description'] = raw_configuration.get('Description')
        configuration['state'] = raw_configuration.get('State')
        configuration['kafka_versions'] = raw_configuration.get('KafkaVersions') or []
        configuration['creation_time'] = creation_time.strftime('%Y-%m-%d %H:%M:%S') if creation_time else None
        configuration['latest_revision'] = latest_revision.get('Revision')
        configuration['latest_revision_creation_time'] = \
            revision_creation_time.strftime('%Y-%m-%d %H:%M:%S') if revision_creation_time else None
        # Properties of the latest revision, which is not necessarily the one any cluster runs
        configuration['server_properties'] = raw_configuration.get('server_properties') or {}

        return get_non_provider_id(configuration['name']), configuration
