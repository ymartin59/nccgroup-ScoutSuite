from typing import Dict, List

from ScoutSuite.core.console import print_exception
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.utils import decode_user_data


class AutoScalingFacade(AWSBaseFacade):
    async def get_auto_scaling_groups(self, region: str) -> List[Dict]:
        try:
            # The description carries the suspended processes, the enabled metrics, the instances
            # and the tags, so nothing else has to be asked for
            return await AWSFacadeUtils.get_all_pages(
                'autoscaling', region, self.session, 'describe_auto_scaling_groups', 'AutoScalingGroups')
        except Exception as e:
            print_exception(f'Failed to describe Auto Scaling groups: {e}')
            return []

    async def get_launch_configurations(self, region: str) -> List[Dict]:
        """Launch configurations are the launch templates of before, immutable and no longer
        creatable, but the groups that still reference one keep launching instances from it."""

        try:
            launch_configurations = await AWSFacadeUtils.get_all_pages(
                'autoscaling', region, self.session, 'describe_launch_configurations', 'LaunchConfigurations')
        except Exception as e:
            print_exception(f'Failed to describe Auto Scaling launch configurations: {e}')
            return []

        for launch_configuration in launch_configurations:
            if not launch_configuration.get('UserData'):
                continue
            try:
                launch_configuration['user_data'] = decode_user_data(launch_configuration['UserData'])
            except Exception as e:
                print_exception(f'Unable to decode Auto Scaling launch configuration user data: {e}')

        return launch_configurations
