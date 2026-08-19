from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.resources.waf.utils import parse_rules, parse_visibility

# The rule groups AWS publishes as the baseline every web ACL is expected to start from: the core
# rule set covers the OWASP style request patterns, known bad inputs the exploit payloads that are
# already circulating.
# https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
BASELINE_MANAGED_RULE_GROUPS = ('AWSManagedRulesCommonRuleSet',
                                'AWSManagedRulesKnownBadInputsRuleSet')


class WebACLs(AWSResources):
    """The web ACLs of a region. Those of the CLOUDFRONT scope have no region of their own and are
    reported under us-east-1, the endpoint AWS serves them from, with their scope on each of them."""

    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw_web_acl in await self.facade.waf.get_web_acls(self.region):
            id, resource = self._parse_web_acl(raw_web_acl)
            self[id] = resource

    def _parse_web_acl(self, raw_web_acl):
        rules = parse_rules(raw_web_acl.get('Rules'))

        web_acl = {}
        web_acl['id'] = raw_web_acl['Id']
        web_acl['name'] = raw_web_acl['Name']
        web_acl['arn'] = raw_web_acl['ARN']
        web_acl['region'] = self.region
        web_acl['scope'] = raw_web_acl.get('Scope')
        web_acl['description'] = raw_web_acl.get('Description')
        web_acl['capacity'] = raw_web_acl.get('Capacity')
        web_acl['label_namespace'] = raw_web_acl.get('LabelNamespace')
        # Web ACLs a Firewall Manager policy owns are not editable in the account they appear in
        web_acl['managed_by_firewall_manager'] = bool(raw_web_acl.get('ManagedByFirewallManager'))
        web_acl['token_domains'] = raw_web_acl.get('TokenDomains') or []
        # The size of the request body WAF looks at, past which the rules inspect nothing
        web_acl['request_body_inspection'] = \
            (raw_web_acl.get('AssociationConfig') or {}).get('RequestBody') or {}

        self._parse_rules(raw_web_acl, rules, web_acl)
        parse_visibility(raw_web_acl, web_acl, rules)
        self._parse_logging(raw_web_acl, web_acl)
        self._parse_associations(raw_web_acl, web_acl)

        return web_acl['id'], web_acl

    @staticmethod
    def _parse_rules(raw_web_acl, rules, web_acl):
        """What the ACL actually does to a request. The default action decides the requests no rule
        matched, and each rule decides the ones it did, so an ACL only refuses anything if at least
        one of the two is set to stop a request."""

        # An action is reported as a single key, here Allow or Block
        default_action = next(iter(raw_web_acl.get('DefaultAction') or {}), None)

        web_acl['default_action'] = default_action
        web_acl['rules'] = rules
        web_acl['rules_count'] = len(rules)

        web_acl['managed_rule_groups'] = [rule['managed_rule_group'] for rule in rules
                                          if rule['managed_rule_group']]
        web_acl['referenced_rule_groups'] = [rule['rule_group_arn'] for rule in rules
                                             if rule['rule_group_arn']]
        web_acl['has_baseline_managed_rule_groups'] = any(
            group.split('/')[-1] in BASELINE_MANAGED_RULE_GROUPS
            for group in web_acl['managed_rule_groups'])

        # A rate based rule is the only thing in a web ACL that reacts to the volume a single source
        # sends, rather than to the contents of one request
        web_acl['rate_based_rules'] = [rule['name'] for rule in rules if rule['rate_limit']]

        # Left in Count, a rule is still evaluated and still labels the request, but lets it through
        web_acl['rules_in_count_mode'] = [rule['name'] for rule in rules if rule['action'] == 'Count']
        web_acl['rule_groups_overridden_to_count'] = [rule['name'] for rule in rules
                                                      if rule['override_action'] == 'Count']
        web_acl['rules_with_overridden_actions'] = [rule['name'] for rule in rules
                                                    if rule['overridden_rules']]

        web_acl['blocking_rules_count'] = len([rule for rule in rules if rule['enforcing']])
        web_acl['blocks_requests'] = \
            default_action == 'Block' or web_acl['blocking_rules_count'] > 0

    @staticmethod
    def _parse_logging(raw_web_acl, web_acl):
        """WAF keeps no record of the requests it inspected unless a logging configuration sends them
        somewhere. What it then writes is the request as it arrived, headers included, so the fields
        holding credentials have to be named for WAF to leave them out."""

        logging_configuration = raw_web_acl.get('logging_configuration') or {}
        data_protections = \
            (raw_web_acl.get('DataProtectionConfig') or {}).get('DataProtections') or []

        web_acl['logging_enabled'] = bool(logging_configuration)
        web_acl['log_destinations'] = logging_configuration.get('LogDestinationConfigs') or []
        web_acl['redacted_fields'] = \
            [WebACLs._describe_field(field) for field in logging_configuration.get('RedactedFields') or []]
        # A filter may keep only part of the traffic, DROP as a default behaviour meaning everything
        # no filter matched is discarded before it reaches the destination
        web_acl['logging_filter'] = logging_configuration.get('LoggingFilter')
        web_acl['logging_filter_default_behavior'] = \
            (logging_configuration.get('LoggingFilter') or {}).get('DefaultBehavior')
        web_acl['logging_scope'] = logging_configuration.get('LogScope')
        # The newer way of keeping sensitive data out of the logs, by hashing or substituting a field
        # rather than dropping it
        web_acl['data_protections'] = [WebACLs._describe_field(protection.get('Field'))
                                       for protection in data_protections]
        web_acl['logging_redaction_configured'] = \
            bool(web_acl['redacted_fields']) or bool(web_acl['data_protections'])

    @staticmethod
    def _parse_associations(raw_web_acl, web_acl):
        """The resources the ACL is in front of. An ACL that is attached to nothing inspects nothing,
        whatever its rules say."""

        associated_resources = raw_web_acl.get('associated_resources')
        # None means the association could not be read, which is not the same as protecting nothing
        if associated_resources is None:
            web_acl['associated_resources'] = {}
            web_acl['associated_resources_count'] = None
            web_acl['associated_resource_types'] = []
            return

        web_acl['associated_resources'] = associated_resources
        web_acl['associated_resources_count'] = len(associated_resources)
        web_acl['associated_resource_types'] = sorted(set(associated_resources.values()))

    @staticmethod
    def _describe_field(field_to_match):
        """Name a request field the way the console does, so a redaction can be read without going
        back to the API shape it came from."""

        if not field_to_match:
            return None

        name = next(iter(field_to_match), None)
        argument = (field_to_match.get(name) or {}).get('Name') if name else None

        return f'{name}:{argument}' if argument else name
