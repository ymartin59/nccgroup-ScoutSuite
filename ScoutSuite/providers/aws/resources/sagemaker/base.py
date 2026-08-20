from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.regions import Regions
from ScoutSuite.providers.aws.resources.sagemaker.domains import Domains
from ScoutSuite.providers.aws.resources.sagemaker.endpoints import Endpoints
from ScoutSuite.providers.aws.resources.sagemaker.models import Models
from ScoutSuite.providers.aws.resources.sagemaker.notebook_instances import NotebookInstances
from ScoutSuite.providers.aws.resources.sagemaker.training_jobs import TrainingJobs


class SageMaker(Regions):
    _children = [
        (NotebookInstances, 'notebook_instances'),
        (Domains, 'domains'),
        (Endpoints, 'endpoints'),
        (Models, 'models'),
        (TrainingJobs, 'training_jobs')
    ]

    def __init__(self, facade: AWSFacade):
        super().__init__('sagemaker', facade)
