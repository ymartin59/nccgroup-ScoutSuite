from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources

# Regions available in every account without any action. Every other one has to be enabled, and can
# be disabled again.
ENABLED_BY_DEFAULT = 'ENABLED_BY_DEFAULT'

# A region being enabled, or on its way to being enabled, is a region where resources can exist. A
# region on its way out is left aside: the decision to close it has already been taken.
ENABLED_STATUSES = [ENABLED_BY_DEFAULT, 'ENABLED', 'ENABLING']


class RegionOptStatus(AWSResources):
    def __init__(self, facade: AWSFacade):
        super().__init__(facade)
        self.partition = facade.partition
        self.service = 'account'
        self.resource_type = 'region'

    async def fetch_all(self):
        raw_regions = await self.facade.account.get_regions()
        for raw_region in raw_regions:
            id, region = self._parse_region(raw_region)
            self[id] = region

    @staticmethod
    def _parse_region(raw_region):
        region = {}
        region['id'] = region['name'] = region['region'] = raw_region.get('RegionName')
        region['opt_status'] = raw_region.get('RegionOptStatus')
        region['enabled'] = region['opt_status'] in ENABLED_STATUSES
        region['enabled_by_default'] = region['opt_status'] == ENABLED_BY_DEFAULT

        # A region somebody deliberately turned on. It carries the same exposure as a default one
        # without having been part of any original design, and it can be turned off again.
        region['enabled_by_opt_in'] = region['enabled'] and not region['enabled_by_default']

        return region['id'], region
