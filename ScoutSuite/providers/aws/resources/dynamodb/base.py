from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.regions import Regions
from .dax_clusters import DaxClusters
from .tables import Tables


class DynamoDB(Regions):
    _children = [
        (Tables, 'tables'),
        (DaxClusters, 'dax_clusters')
    ]

    def __init__(self, facade: AWSFacade):
        super(DynamoDB, self).__init__('dynamodb', facade)
