from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.mq.brokers import Brokers
from ScoutSuite.providers.aws.resources.mq.configurations import Configurations
from ScoutSuite.providers.aws.resources.regions import Regions


class MQ(Regions):
    _children = [
        (Brokers, 'brokers'),
        (Configurations, 'configurations')
    ]

    def __init__(self, facade: AWSFacade):
        super().__init__('mq', facade)
