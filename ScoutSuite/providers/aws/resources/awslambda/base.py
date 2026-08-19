from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.regions import Regions

from .functions import Functions
from .layers import Layers


class Lambdas(Regions):
    _children = [
        (Functions, 'functions'),
        (Layers, 'layers')
    ]

    def __init__(self, facade: AWSFacade):
        super().__init__('lambda', facade)
