from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSCompositeResources
from .contacts import Contacts
from .region_opt_status import RegionOptStatus

class Account(AWSCompositeResources):
    _children = [
        (Contacts, 'contacts'),
        (RegionOptStatus, 'region_opt_status')
    ]

    def __init__(self, facade: AWSFacade):
        super().__init__(facade)
        self.service = 'account'

    async def fetch_all(self, partition_name='aws', **kwargs):
        await self._fetch_children(self)
