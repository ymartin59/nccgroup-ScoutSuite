from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.athena.data_catalogs import DataCatalogs
from ScoutSuite.providers.aws.resources.athena.work_groups import WorkGroups
from ScoutSuite.providers.aws.resources.regions import Regions


class Athena(Regions):
    _children = [
        (WorkGroups, 'work_groups'),
        (DataCatalogs, 'data_catalogs')
    ]

    def __init__(self, facade: AWSFacade):
        super().__init__('athena', facade)
