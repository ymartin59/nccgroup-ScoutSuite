"""Parsing shared by web ACLs and rule groups: both hold a list of rules built the same way, and both
carry a visibility configuration deciding what WAF records about the traffic it inspects."""

# Actions that stop a request from reaching the protected resource. CAPTCHA and Challenge do not
# refuse it outright, but a client that cannot answer them never gets through either.
ENFORCING_ACTIONS = ('Block', 'Captcha', 'Challenge')

# Actions a managed rule group's own rules may be overridden to. Anything other than Block leaves the
# rule evaluated, and labelled, but no longer able to stop the request.
NON_ENFORCING_OVERRIDES = ('Count', 'Allow')


def parse_rules(raw_rules):
    """Turn the rules of a web ACL or of a rule group into a list carrying, for each of them, what it
    inspects, what it does with a match, and whether WAF records anything about it."""

    return [_parse_rule(raw_rule) for raw_rule in raw_rules or []]


def _parse_rule(raw_rule):
    statement = raw_rule.get('Statement') or {}
    visibility = raw_rule.get('VisibilityConfig') or {}
    managed_rule_group = statement.get('ManagedRuleGroupStatement') or {}
    rule_group_reference = statement.get('RuleGroupReferenceStatement') or {}
    rate_based = statement.get('RateBasedStatement') or {}

    action = _parse_action(raw_rule.get('Action'))
    override_action = _parse_action(raw_rule.get('OverrideAction'))

    rule = {}
    rule['name'] = raw_rule.get('Name')
    rule['priority'] = raw_rule.get('Priority')
    # A rule holds exactly one statement, whose single key names what it inspects
    rule['statement_type'] = next(iter(statement), None)
    rule['action'] = action
    rule['override_action'] = override_action
    rule['vendor'] = managed_rule_group.get('VendorName')
    rule['managed_rule_group'] = _managed_rule_group_name(managed_rule_group)
    # Absent when the rule group follows the default version AWS keeps current
    rule['managed_rule_group_version'] = managed_rule_group.get('Version')
    rule['rule_group_arn'] = rule_group_reference.get('ARN')
    rule['overridden_rules'] = _parse_overridden_rules(managed_rule_group or rule_group_reference)
    rule['rate_limit'] = rate_based.get('Limit')
    rule['sampled_requests_enabled'] = bool(visibility.get('SampledRequestsEnabled'))
    rule['cloudwatch_metrics_enabled'] = bool(visibility.get('CloudWatchMetricsEnabled'))
    rule['enforcing'] = _is_enforcing(action, override_action)

    return rule


def _parse_action(raw_action):
    """An action is reported as a single key mapping to an empty structure, so the key is the action.
    An unoverridden rule group carries the literal key 'None'."""

    if not raw_action:
        return None
    return next(iter(raw_action), None)


def _managed_rule_group_name(managed_rule_group):
    if not managed_rule_group.get('Name'):
        return None
    return f'{managed_rule_group.get("VendorName")}/{managed_rule_group["Name"]}'


def _parse_overridden_rules(reference_statement):
    """Names of the rules of a referenced group that no longer block. RuleActionOverrides is the
    current way of doing it, ExcludedRules the deprecated one, and both amount to the same."""

    overridden = [override['Name']
                  for override in reference_statement.get('RuleActionOverrides') or []
                  if override.get('Name')
                  and _parse_action(override.get('ActionToUse')) in NON_ENFORCING_OVERRIDES]
    overridden += [excluded['Name'] for excluded in reference_statement.get('ExcludedRules') or []
                   if excluded.get('Name')]

    return overridden


def _is_enforcing(action, override_action):
    # A rule referencing a group carries an override rather than an action of its own: 'None' leaves
    # the group's rules to act as they are written, 'Count' silences every one of them at once
    if override_action:
        return override_action != 'Count'
    return action in ENFORCING_ACTIONS


def parse_visibility(raw_resource, resource, rules):
    """Report what WAF records, at the level of the resource and of each of its rules. Metrics and
    sampled requests are the only account of what a rule matched: without them a rule that blocks
    legitimate traffic, or one that never matches anything, both look the same from outside."""

    visibility = raw_resource.get('VisibilityConfig') or {}

    resource['sampled_requests_enabled'] = bool(visibility.get('SampledRequestsEnabled'))
    resource['cloudwatch_metrics_enabled'] = bool(visibility.get('CloudWatchMetricsEnabled'))
    resource['cloudwatch_metric_name'] = visibility.get('MetricName')

    resource['rules_without_sampled_requests'] = \
        [rule['name'] for rule in rules if not rule['sampled_requests_enabled']]
    resource['rules_without_cloudwatch_metrics'] = \
        [rule['name'] for rule in rules if not rule['cloudwatch_metrics_enabled']]

    resource['sampled_requests_fully_enabled'] = \
        resource['sampled_requests_enabled'] and not resource['rules_without_sampled_requests']
    resource['cloudwatch_metrics_fully_enabled'] = \
        resource['cloudwatch_metrics_enabled'] and not resource['rules_without_cloudwatch_metrics']
