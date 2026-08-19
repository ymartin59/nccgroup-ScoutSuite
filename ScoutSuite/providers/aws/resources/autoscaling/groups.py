from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id

# Processes whose suspension stops the group from doing the thing it is there for. Suspending any
# of these leaves instances that failed, or that an attacker got hold of, running and in service.
SECURITY_RELEVANT_PROCESSES = [
    'Launch',
    'Terminate',
    'HealthCheck',
    'ReplaceUnhealthy',
    'AddToLoadBalancer',
]


class AutoScalingGroups(AWSResources):
    """The Auto Scaling groups of a region. A group decides where its instances land, what replaces
    them and from which launch template or launch configuration they are built, so it is the thing
    that keeps applying a configuration long after the instances first created from it are gone."""

    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw_group in await self.facade.autoscaling.get_auto_scaling_groups(self.region):
            name, resource = self._parse_group(raw_group)
            self[name] = resource

    def _parse_group(self, raw_group):
        created_time = raw_group.get('CreatedTime')

        group = {}
        group['id'] = raw_group['AutoScalingGroupName']
        group['name'] = raw_group['AutoScalingGroupName']
        group['arn'] = raw_group.get('AutoScalingGroupARN')
        group['region'] = self.region
        group['created_time'] = created_time.strftime('%Y-%m-%d %H:%M:%S') if created_time else None
        group['status'] = raw_group.get('Status')
        group['service_linked_role_arn'] = raw_group.get('ServiceLinkedRoleARN')

        group['min_size'] = raw_group.get('MinSize')
        group['max_size'] = raw_group.get('MaxSize')
        group['desired_capacity'] = raw_group.get('DesiredCapacity')
        group['instances_count'] = len(raw_group.get('Instances') or [])
        group['default_cooldown'] = raw_group.get('DefaultCooldown')
        group['default_instance_warmup'] = raw_group.get('DefaultInstanceWarmup')
        # An instance that is never replaced keeps running the AMI, the packages and the
        # credentials it was created with, however old they have become
        group['max_instance_lifetime'] = raw_group.get('MaxInstanceLifetime')
        group['termination_policies'] = raw_group.get('TerminationPolicies') or []
        group['new_instances_protected_from_scale_in'] = raw_group.get('NewInstancesProtectedFromScaleIn')
        group['capacity_rebalance'] = raw_group.get('CapacityRebalance')
        group['instance_maintenance_policy'] = raw_group.get('InstanceMaintenancePolicy') or {}

        self._parse_placement(raw_group, group)
        self._parse_launch_source(raw_group, group)
        self._parse_health_checks(raw_group, group)
        self._parse_processes(raw_group, group)
        self._parse_tags(raw_group, group)

        return get_non_provider_id(group['name']), group

    @staticmethod
    def _parse_placement(raw_group, group):
        availability_zones = raw_group.get('AvailabilityZones') or []
        # The subnets are handed over as one comma separated string
        subnets = [subnet for subnet in (raw_group.get('VPCZoneIdentifier') or '').split(',') if subnet]

        group['availability_zones'] = availability_zones
        group['availability_zones_count'] = len(availability_zones)
        group['subnets'] = subnets
        # A group confined to a single zone goes down with that zone, and the capacity it was
        # meant to keep available goes with it
        group['single_availability_zone'] = len(availability_zones) < 2

    @staticmethod
    def _parse_launch_source(raw_group, group):
        """Find the template or configuration the group builds its instances from. It is named
        either directly, or inside a mixed instances policy, and a group created long enough ago
        may still point at a launch configuration instead."""

        mixed_instances_policy = raw_group.get('MixedInstancesPolicy') or {}
        launch_template = raw_group.get('LaunchTemplate') or \
            (mixed_instances_policy.get('LaunchTemplate') or {}).get('LaunchTemplateSpecification') or {}

        group['launch_template_id'] = launch_template.get('LaunchTemplateId')
        group['launch_template_name'] = launch_template.get('LaunchTemplateName')
        # $Default and $Latest follow the template, a number pins the group to one version and
        # keeps it there whatever the template becomes
        group['launch_template_version'] = launch_template.get('Version')
        group['launch_configuration_name'] = raw_group.get('LaunchConfigurationName')
        group['uses_launch_template'] = bool(launch_template)
        group['uses_launch_configuration'] = bool(raw_group.get('LaunchConfigurationName'))

        overrides = (mixed_instances_policy.get('LaunchTemplate') or {}).get('Overrides') or []
        group['uses_mixed_instances_policy'] = bool(mixed_instances_policy)
        group['instance_types'] = [override['InstanceType'] for override in overrides
                                   if override.get('InstanceType')]
        instances_distribution = mixed_instances_policy.get('InstancesDistribution') or {}
        group['on_demand_base_capacity'] = instances_distribution.get('OnDemandBaseCapacity')
        group['spot_allocation_strategy'] = instances_distribution.get('SpotAllocationStrategy')

    @staticmethod
    def _parse_health_checks(raw_group, group):
        load_balancer_names = raw_group.get('LoadBalancerNames') or []
        target_group_arns = raw_group.get('TargetGroupARNs') or []
        traffic_sources = raw_group.get('TrafficSources') or []
        health_check_type = raw_group.get('HealthCheckType')

        group['load_balancer_names'] = load_balancer_names
        group['target_group_arns'] = target_group_arns
        group['traffic_sources'] = [source.get('Identifier') for source in traffic_sources
                                    if source.get('Identifier')]
        group['attached_to_load_balancer'] = \
            bool(load_balancer_names or target_group_arns or traffic_sources)

        group['health_check_type'] = health_check_type
        group['health_check_grace_period'] = raw_group.get('HealthCheckGracePeriod')
        # An EC2 health check only sees whether the instance is running, so an instance answering
        # the load balancer with errors, or no longer answering at all, stays in service
        group['elb_health_check_enabled'] = health_check_type in ('ELB', 'VPC_LATTICE')

    @staticmethod
    def _parse_processes(raw_group, group):
        suspended_processes = [process['ProcessName']
                               for process in raw_group.get('SuspendedProcesses') or []
                               if process.get('ProcessName')]

        group['suspended_processes'] = suspended_processes
        group['suspended_processes_count'] = len(suspended_processes)
        group['security_relevant_processes_suspended'] = \
            [process for process in suspended_processes if process in SECURITY_RELEVANT_PROCESSES]

        enabled_metrics = [metric['Metric'] for metric in raw_group.get('EnabledMetrics') or []
                           if metric.get('Metric')]
        group['enabled_metrics'] = enabled_metrics
        group['metrics_collection_enabled'] = bool(enabled_metrics)

    @staticmethod
    def _parse_tags(raw_group, group):
        tags = raw_group.get('Tags') or []

        group['tags'] = [{'key': tag.get('Key'),
                          'value': tag.get('Value'),
                          'propagate_at_launch': tag.get('PropagateAtLaunch')}
                         for tag in tags]
        # A tag that is not propagated never reaches the instances, so anything keyed on it,
        # tag-based IAM conditions and ownership among them, does not apply to them
        group['tags_not_propagated'] = [tag.get('Key') for tag in tags
                                        if not tag.get('PropagateAtLaunch')]
