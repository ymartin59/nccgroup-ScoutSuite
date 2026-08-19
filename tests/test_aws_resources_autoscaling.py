import unittest

from datetime import datetime

from ScoutSuite.providers.aws.resources.autoscaling.groups import AutoScalingGroups
from ScoutSuite.providers.aws.resources.autoscaling.launchconfigurations import LaunchConfigurations


class Facade:
    partition = 'aws'
    owner_id = '123456789012'


def parse_group(**attributes):
    raw_group = {'AutoScalingGroupName': 'web-asg'}
    raw_group.update(attributes)
    _, group = AutoScalingGroups(Facade(), 'eu-west-1')._parse_group(raw_group)
    return group


def parse_launch_configuration(**attributes):
    raw_configuration = {'LaunchConfigurationName': 'web-lc'}
    raw_configuration.update(attributes)
    _, configuration = \
        LaunchConfigurations(Facade(), 'eu-west-1')._parse_launch_configuration(raw_configuration)
    return configuration


class TestAWSAutoScalingGroupPlacement(unittest.TestCase):

    def test_subnets_are_split(self):
        group = parse_group(AvailabilityZones=['eu-west-1a', 'eu-west-1b'],
                            VPCZoneIdentifier='subnet-1,subnet-2')

        assert group['subnets'] == ['subnet-1', 'subnet-2']
        assert group['availability_zones_count'] == 2
        assert group['single_availability_zone'] is False

    def test_single_availability_zone(self):
        group = parse_group(AvailabilityZones=['eu-west-1a'], VPCZoneIdentifier='subnet-1')

        assert group['single_availability_zone'] is True

    def test_group_without_subnets(self):
        group = parse_group(AvailabilityZones=['eu-west-1a', 'eu-west-1b'])

        assert group['subnets'] == []


class TestAWSAutoScalingGroupLaunchSource(unittest.TestCase):

    def test_launch_template(self):
        group = parse_group(LaunchTemplate={'LaunchTemplateId': 'lt-01234567890123456',
                                            'LaunchTemplateName': 'web',
                                            'Version': '$Default'})

        assert group['uses_launch_template'] is True
        assert group['uses_launch_configuration'] is False
        assert group['launch_template_id'] == 'lt-01234567890123456'
        assert group['launch_template_version'] == '$Default'
        assert group['uses_mixed_instances_policy'] is False

    def test_launch_template_inside_a_mixed_instances_policy(self):
        group = parse_group(MixedInstancesPolicy={
            'LaunchTemplate': {
                'LaunchTemplateSpecification': {'LaunchTemplateId': 'lt-01234567890123456',
                                                'LaunchTemplateName': 'web',
                                                'Version': '$Latest'},
                'Overrides': [{'InstanceType': 'm6i.large'}, {'InstanceType': 'm6a.large'}],
            },
            'InstancesDistribution': {'OnDemandBaseCapacity': 1,
                                      'SpotAllocationStrategy': 'price-capacity-optimized'},
        })

        assert group['uses_launch_template'] is True
        assert group['launch_template_name'] == 'web'
        assert group['uses_mixed_instances_policy'] is True
        assert group['instance_types'] == ['m6i.large', 'm6a.large']
        assert group['on_demand_base_capacity'] == 1

    def test_launch_configuration(self):
        group = parse_group(LaunchConfigurationName='legacy-lc')

        assert group['uses_launch_configuration'] is True
        assert group['uses_launch_template'] is False
        assert group['launch_configuration_name'] == 'legacy-lc'


class TestAWSAutoScalingGroupHealthChecks(unittest.TestCase):

    def test_load_balancer_with_elb_health_checks(self):
        group = parse_group(HealthCheckType='ELB', LoadBalancerNames=['legacy-elb'])

        assert group['attached_to_load_balancer'] is True
        assert group['elb_health_check_enabled'] is True

    def test_target_group_with_ec2_health_checks(self):
        group = parse_group(HealthCheckType='EC2',
                            TargetGroupARNs=['arn:aws:elasticloadbalancing:eu-west-1:1:targetgroup/web/1'])

        assert group['attached_to_load_balancer'] is True
        assert group['elb_health_check_enabled'] is False

    def test_traffic_source_counts_as_an_attachment(self):
        group = parse_group(HealthCheckType='EC2',
                            TrafficSources=[{'Identifier': 'arn:aws:vpc-lattice:eu-west-1:1:targetgroup/tg-1',
                                             'Type': 'vpc-lattice'}])

        assert group['attached_to_load_balancer'] is True
        assert group['traffic_sources'] == ['arn:aws:vpc-lattice:eu-west-1:1:targetgroup/tg-1']
        assert group['elb_health_check_enabled'] is False

    def test_vpc_lattice_health_checks(self):
        group = parse_group(HealthCheckType='VPC_LATTICE',
                            TrafficSources=[{'Identifier': 'arn:aws:vpc-lattice:eu-west-1:1:targetgroup/tg-1'}])

        assert group['elb_health_check_enabled'] is True

    def test_group_serving_no_traffic(self):
        group = parse_group(HealthCheckType='EC2')

        assert group['attached_to_load_balancer'] is False
        assert group['elb_health_check_enabled'] is False


class TestAWSAutoScalingGroupProcesses(unittest.TestCase):

    def test_suspended_processes(self):
        group = parse_group(SuspendedProcesses=[
            {'ProcessName': 'ReplaceUnhealthy', 'SuspensionReason': 'User suspended'},
            {'ProcessName': 'AZRebalance', 'SuspensionReason': 'User suspended'}])

        assert group['suspended_processes'] == ['ReplaceUnhealthy', 'AZRebalance']
        assert group['suspended_processes_count'] == 2
        # Rebalancing across zones stopping is a capacity decision, unhealthy instances no longer
        # being replaced is not
        assert group['security_relevant_processes_suspended'] == ['ReplaceUnhealthy']

    def test_no_suspended_process(self):
        group = parse_group(EnabledMetrics=[{'Metric': 'GroupInServiceInstances'}])

        assert group['suspended_processes'] == []
        assert group['metrics_collection_enabled'] is True

    def test_no_metrics_collected(self):
        group = parse_group()

        assert group['enabled_metrics'] == []
        assert group['metrics_collection_enabled'] is False


class TestAWSAutoScalingGroupTags(unittest.TestCase):

    def test_tags_reaching_the_instances(self):
        group = parse_group(CreatedTime=datetime(2025, 3, 4, 9, 20, 0), Tags=[
            {'Key': 'Name', 'Value': 'web', 'PropagateAtLaunch': True},
            {'Key': 'Owner', 'Value': 'platform', 'PropagateAtLaunch': False}])

        assert group['created_time'] == '2025-03-04 09:20:00'
        assert group['tags_not_propagated'] == ['Owner']


class TestAWSLaunchConfiguration(unittest.TestCase):

    def test_imdsv2_required(self):
        configuration = parse_launch_configuration(
            MetadataOptions={'HttpTokens': 'required', 'HttpPutResponseHopLimit': 1})

        assert configuration['imdsv2_required'] is True
        assert configuration['imds_hop_limit_excessive'] is False

    def test_metadata_options_left_out(self):
        configuration = parse_launch_configuration(ImageId='ami-01234567890123456')

        assert configuration['imdsv2_required'] is False
        assert configuration['http_tokens'] is None

    def test_public_address(self):
        configuration = parse_launch_configuration(AssociatePublicIpAddress=True)

        assert configuration['associate_public_ip_address'] is True

    def test_public_address_left_to_the_subnet(self):
        configuration = parse_launch_configuration(ImageId='ami-01234567890123456')

        assert configuration['associate_public_ip_address'] is None

    def test_user_data_secrets(self):
        configuration = parse_launch_configuration(
            UserData='aWdub3JlZA==', user_data='DB_PASSWORD=hunter2\n')

        assert configuration['user_data_secrets']['Flagged Words'] == ['password']

    def test_unencrypted_block_devices(self):
        configuration = parse_launch_configuration(BlockDeviceMappings=[
            {'DeviceName': '/dev/xvda', 'Ebs': {'Encrypted': False}},
            {'DeviceName': '/dev/sdb', 'Ebs': {'Encrypted': True}},
            {'DeviceName': '/dev/sdc', 'VirtualName': 'ephemeral0'}])

        assert configuration['unencrypted_block_devices'] == ['/dev/xvda']
        assert len(configuration['block_devices']) == 2
