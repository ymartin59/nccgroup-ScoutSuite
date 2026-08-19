from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.autoscaling.groups import AutoScalingGroups
from ScoutSuite.providers.aws.resources.autoscaling.launchconfigurations import LaunchConfigurations
from ScoutSuite.providers.aws.resources.regions import Regions


class AutoScaling(Regions):
    _children = [
        (AutoScalingGroups, 'groups'),
        (LaunchConfigurations, 'launch_configurations')
    ]

    def __init__(self, facade: AWSFacade):
        super().__init__('autoscaling', facade)
