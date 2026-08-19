from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.resources.waf.utils import parse_rules, parse_visibility


class RuleGroups(AWSResources):
    """The rule groups the account writes itself, as opposed to the ones a vendor publishes. A rule
    group does nothing on its own, it only takes effect through the web ACLs referencing it."""

    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw_rule_group in await self.facade.waf.get_rule_groups(self.region):
            id, resource = self._parse_rule_group(raw_rule_group)
            self[id] = resource

    def _parse_rule_group(self, raw_rule_group):
        rules = parse_rules(raw_rule_group.get('Rules'))

        rule_group = {}
        rule_group['id'] = raw_rule_group['Id']
        rule_group['name'] = raw_rule_group['Name']
        rule_group['arn'] = raw_rule_group['ARN']
        rule_group['region'] = self.region
        rule_group['scope'] = raw_rule_group.get('Scope')
        rule_group['description'] = raw_rule_group.get('Description')
        rule_group['capacity'] = raw_rule_group.get('Capacity')
        rule_group['label_namespace'] = raw_rule_group.get('LabelNamespace')
        rule_group['rules'] = rules
        rule_group['rules_count'] = len(rules)
        rule_group['rules_in_count_mode'] = [rule['name'] for rule in rules if rule['action'] == 'Count']
        rule_group['blocking_rules_count'] = len([rule for rule in rules if rule['enforcing']])

        parse_visibility(raw_rule_group, rule_group, rules)

        return rule_group['id'], rule_group
