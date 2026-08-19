from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Layers(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        raw_layers = await self.facade.awslambda.get_layers(self.region)
        for raw_layer in raw_layers:
            name, resource = self._parse_layer(raw_layer)
            self[name] = resource

    def _parse_layer(self, raw_layer):
        layer = {}
        layer['name'] = raw_layer.get('LayerName')
        layer['arn'] = raw_layer.get('LayerArn')
        layer['region'] = self.region
        # The version the layer listing considers current, which is not necessarily the only one a
        # function still points at: every published version stays usable until it is deleted
        layer['latest_version'] = (raw_layer.get('LatestMatchingVersion') or {}).get('Version')

        layer['versions'] = {}
        for raw_version in raw_layer.get('versions') or []:
            version = self._parse_version(raw_version)
            layer['versions'][str(version['version'])] = version
        layer['versions_count'] = len(layer['versions'])

        return get_non_provider_id(layer['name']), layer

    @staticmethod
    def _parse_version(raw_version):
        version = {}
        version['version'] = raw_version.get('Version')
        version['arn'] = raw_version.get('LayerVersionArn')
        version['created_date'] = raw_version.get('CreatedDate')
        version['description'] = raw_version.get('Description')
        version['compatible_runtimes'] = raw_version.get('CompatibleRuntimes') or []
        version['compatible_architectures'] = raw_version.get('CompatibleArchitectures') or []
        version['license_info'] = raw_version.get('LicenseInfo')
        # Only set when the version was granted to a principal outside the account, absent otherwise
        if 'policy' in raw_version:
            version['policy'] = raw_version['policy']

        return version
