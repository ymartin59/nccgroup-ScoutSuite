from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.ecr.images import Images
from ScoutSuite.providers.aws.resources.ecr.registry_settings import RegistrySettings
from ScoutSuite.providers.aws.resources.ecr.repositories import Repositories
from ScoutSuite.providers.aws.resources.regions import Regions


class ECR(Regions):
    _children = [
        (Repositories, 'repositories'),
        (Images, 'images'),
        (RegistrySettings, 'registry_settings')
    ]

    def __init__(self, facade: AWSFacade):
        super().__init__('ecr', facade)
