from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.msk.clusters import Clusters
from ScoutSuite.providers.aws.resources.msk.configurations import Configurations
from ScoutSuite.providers.aws.resources.regions import Regions


class MSK(Regions):
    _children = [
        (Clusters, 'clusters'),
        (Configurations, 'configurations')
    ]

    def __init__(self, facade: AWSFacade):
        # MSK is exposed by boto3 under the name of the software it runs
        super().__init__('kafka', facade)
