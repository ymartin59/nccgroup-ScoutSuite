import asyncio
import unittest

from unittest import mock

import boto3

import ScoutSuite.providers.aws.facade.waf as waf_facade
from ScoutSuite.providers.aws.facade.waf import WAFFacade
from ScoutSuite.providers.aws.resources.waf.rule_groups import RuleGroups
from ScoutSuite.providers.aws.resources.waf.utils import parse_rules, parse_visibility
from ScoutSuite.providers.aws.resources.waf.web_acls import WebACLs


def managed_rule_group(name, override='None', vendor='AWS', **statement):
    return {
        'Name': name,
        'Priority': 1,
        'Statement': {'ManagedRuleGroupStatement': dict({'VendorName': vendor, 'Name': name},
                                                        **statement)},
        'OverrideAction': {override: {}},
        'VisibilityConfig': {'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True,
                             'MetricName': name},
    }


def blocking_rule(name, action='Block', **visibility):
    return {
        'Name': name,
        'Priority': 2,
        'Statement': {'SqliMatchStatement': {}},
        'Action': {action: {}},
        'VisibilityConfig': dict({'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True},
                                 **visibility),
    }


class TestAWSWAFRuleParsing(unittest.TestCase):

    def test_managed_rule_group_left_to_its_own_actions(self):
        rule = parse_rules([managed_rule_group('AWSManagedRulesCommonRuleSet')])[0]

        assert rule['statement_type'] == 'ManagedRuleGroupStatement'
        assert rule['managed_rule_group'] == 'AWS/AWSManagedRulesCommonRuleSet'
        assert rule['override_action'] == 'None'
        assert rule['action'] is None
        assert rule['enforcing'] is True

    def test_managed_rule_group_overridden_to_count(self):
        # A Count override silences every rule of the group at once
        rule = parse_rules([managed_rule_group('AWSManagedRulesCommonRuleSet', override='Count')])[0]

        assert rule['override_action'] == 'Count'
        assert rule['enforcing'] is False

    def test_rule_action_overrides_that_disarm_individual_rules(self):
        rule = parse_rules([managed_rule_group(
            'AWSManagedRulesCommonRuleSet',
            RuleActionOverrides=[{'Name': 'SizeRestrictions_BODY', 'ActionToUse': {'Count': {}}},
                                 {'Name': 'GenericLFI_QUERYARGUMENTS', 'ActionToUse': {'Allow': {}}},
                                 {'Name': 'NoUserAgent_HEADER', 'ActionToUse': {'Block': {}}}])])[0]

        # Overriding a rule to Block leaves it able to stop a request, so it is not reported
        assert rule['overridden_rules'] == ['SizeRestrictions_BODY', 'GenericLFI_QUERYARGUMENTS']
        assert rule['enforcing'] is True

    def test_deprecated_excluded_rules_count_as_overridden(self):
        rule = parse_rules([managed_rule_group(
            'AWSManagedRulesCommonRuleSet',
            ExcludedRules=[{'Name': 'CrossSiteScripting_BODY'}])])[0]

        assert rule['overridden_rules'] == ['CrossSiteScripting_BODY']

    def test_actions_that_stop_a_request(self):
        for action in ('Block', 'Captcha', 'Challenge'):
            assert parse_rules([blocking_rule('rule', action=action)])[0]['enforcing'] is True

        for action in ('Count', 'Allow'):
            assert parse_rules([blocking_rule('rule', action=action)])[0]['enforcing'] is False

    def test_rate_based_rule(self):
        rule = parse_rules([{
            'Name': 'flood',
            'Priority': 0,
            'Statement': {'RateBasedStatement': {'Limit': 2000, 'AggregateKeyType': 'IP'}},
            'Action': {'Block': {}},
            'VisibilityConfig': {},
        }])[0]

        assert rule['rate_limit'] == 2000
        assert rule['statement_type'] == 'RateBasedStatement'
        assert rule['sampled_requests_enabled'] is False
        assert rule['cloudwatch_metrics_enabled'] is False

    def test_rule_group_reference(self):
        rule = parse_rules([{
            'Name': 'own-group',
            'Priority': 3,
            'Statement': {'RuleGroupReferenceStatement': {
                'ARN': 'arn:aws:wafv2:eu-west-1:123456789012:regional/rulegroup/own/1',
                'RuleActionOverrides': [{'Name': 'noisy', 'ActionToUse': {'Count': {}}}]}},
            'OverrideAction': {'None': {}},
            'VisibilityConfig': {},
        }])[0]

        assert rule['rule_group_arn'].endswith('rulegroup/own/1')
        assert rule['managed_rule_group'] is None
        assert rule['overridden_rules'] == ['noisy']


class TestAWSWAFVisibility(unittest.TestCase):

    def test_visibility_holds_only_when_every_rule_reports(self):
        rules = parse_rules([blocking_rule('seen'),
                             blocking_rule('unseen', SampledRequestsEnabled=False,
                                           CloudWatchMetricsEnabled=False)])
        resource = {}
        parse_visibility({'VisibilityConfig': {'SampledRequestsEnabled': True,
                                               'CloudWatchMetricsEnabled': True,
                                               'MetricName': 'acl'}}, resource, rules)

        assert resource['sampled_requests_enabled'] is True
        assert resource['cloudwatch_metrics_enabled'] is True
        assert resource['rules_without_sampled_requests'] == ['unseen']
        assert resource['rules_without_cloudwatch_metrics'] == ['unseen']
        assert resource['sampled_requests_fully_enabled'] is False
        assert resource['cloudwatch_metrics_fully_enabled'] is False

    def test_visibility_disabled_on_the_resource_itself(self):
        resource = {}
        parse_visibility({'VisibilityConfig': {'SampledRequestsEnabled': False,
                                               'CloudWatchMetricsEnabled': True}}, resource, [])

        assert resource['sampled_requests_fully_enabled'] is False
        assert resource['cloudwatch_metrics_fully_enabled'] is True


class TestAWSWAFWebACL(unittest.TestCase):

    @staticmethod
    def _parse(raw_web_acl):
        raw_web_acl.setdefault('Id', '11111111-2222-3333-4444-555555555555')
        raw_web_acl.setdefault('Name', 'acl')
        raw_web_acl.setdefault('ARN', 'arn:aws:wafv2:eu-west-1:123456789012:regional/webacl/acl/1')
        raw_web_acl.setdefault('Scope', 'REGIONAL')
        return WebACLs(None, 'eu-west-1')._parse_web_acl(raw_web_acl)[1]

    def test_web_acl_that_blocks_through_a_managed_rule_group(self):
        web_acl = self._parse({
            'DefaultAction': {'Allow': {}},
            'Rules': [managed_rule_group('AWSManagedRulesCommonRuleSet')],
        })

        assert web_acl['default_action'] == 'Allow'
        assert web_acl['rules_count'] == 1
        assert web_acl['blocking_rules_count'] == 1
        assert web_acl['blocks_requests'] is True
        assert web_acl['managed_rule_groups'] == ['AWS/AWSManagedRulesCommonRuleSet']
        assert web_acl['has_baseline_managed_rule_groups'] is True
        assert web_acl['rate_based_rules'] == []

    def test_web_acl_whose_only_rule_group_is_overridden(self):
        # Every rule is evaluated and counted, and every request is still served
        web_acl = self._parse({
            'DefaultAction': {'Allow': {}},
            'Rules': [managed_rule_group('AWSManagedRulesCommonRuleSet', override='Count')],
        })

        assert web_acl['blocking_rules_count'] == 0
        assert web_acl['blocks_requests'] is False
        assert web_acl['rule_groups_overridden_to_count'] == ['AWSManagedRulesCommonRuleSet']

    def test_web_acl_that_refuses_by_default(self):
        web_acl = self._parse({'DefaultAction': {'Block': {}}, 'Rules': []})

        assert web_acl['default_action'] == 'Block'
        assert web_acl['blocks_requests'] is True
        assert web_acl['rules_count'] == 0

    def test_use_case_managed_rule_groups_are_not_the_baseline(self):
        web_acl = self._parse({
            'DefaultAction': {'Allow': {}},
            'Rules': [managed_rule_group('AWSManagedRulesBotControlRuleSet')],
        })

        assert web_acl['managed_rule_groups'] == ['AWS/AWSManagedRulesBotControlRuleSet']
        assert web_acl['has_baseline_managed_rule_groups'] is False

    def test_logging_configuration_with_redactions(self):
        web_acl = self._parse({
            'DefaultAction': {'Block': {}},
            'Rules': [],
            'logging_configuration': {
                'LogDestinationConfigs': ['arn:aws:logs:eu-west-1:123456789012:log-group:aws-waf-logs-acl'],
                'RedactedFields': [{'SingleHeader': {'Name': 'authorization'}}, {'QueryString': {}}],
                'LoggingFilter': {'DefaultBehavior': 'KEEP', 'Filters': []},
            },
        })

        assert web_acl['logging_enabled'] is True
        assert web_acl['redacted_fields'] == ['SingleHeader:authorization', 'QueryString']
        assert web_acl['logging_redaction_configured'] is True
        assert web_acl['logging_filter_default_behavior'] == 'KEEP'

    def test_data_protection_counts_as_redaction(self):
        web_acl = self._parse({
            'DefaultAction': {'Block': {}},
            'Rules': [],
            'logging_configuration': {'LogDestinationConfigs': ['arn:aws:s3:::aws-waf-logs-acl']},
            'DataProtectionConfig': {'DataProtections': [
                {'Field': {'SingleHeader': {'Name': 'cookie'}}, 'Action': 'HASH'}]},
        })

        assert web_acl['redacted_fields'] == []
        assert web_acl['data_protections'] == ['SingleHeader:cookie']
        assert web_acl['logging_redaction_configured'] is True

    def test_web_acl_without_logging(self):
        web_acl = self._parse({'DefaultAction': {'Block': {}}, 'Rules': []})

        assert web_acl['logging_enabled'] is False
        assert web_acl['log_destinations'] == []
        assert web_acl['logging_redaction_configured'] is False

    def test_associated_resources(self):
        web_acl = self._parse({
            'DefaultAction': {'Block': {}},
            'Rules': [],
            'associated_resources': {
                'arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/front/1':
                    'APPLICATION_LOAD_BALANCER'},
        })

        assert web_acl['associated_resources_count'] == 1
        assert web_acl['associated_resource_types'] == ['APPLICATION_LOAD_BALANCER']

    def test_associations_that_could_not_be_read_are_left_undecided(self):
        # Reporting zero here would turn a denied ListResourcesForWebACL into a finding
        web_acl = self._parse({'DefaultAction': {'Block': {}}, 'Rules': [],
                               'associated_resources': None})

        assert web_acl['associated_resources_count'] is None
        assert web_acl['associated_resource_types'] == []


class TestAWSWAFRuleGroup(unittest.TestCase):

    def test_rule_group(self):
        rule_group = RuleGroups(None, 'eu-west-1')._parse_rule_group({
            'Id': '99999999-8888-7777-6666-555555555555',
            'Name': 'own',
            'ARN': 'arn:aws:wafv2:eu-west-1:123456789012:regional/rulegroup/own/1',
            'Scope': 'REGIONAL',
            'Capacity': 50,
            'Rules': [blocking_rule('block-sqli'), blocking_rule('count-only', action='Count')],
            'VisibilityConfig': {'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True},
        })[1]

        assert rule_group['rules_count'] == 2
        assert rule_group['blocking_rules_count'] == 1
        assert rule_group['rules_in_count_mode'] == ['count-only']
        assert rule_group['cloudwatch_metrics_fully_enabled'] is True

    def test_empty_rule_group(self):
        rule_group = RuleGroups(None, 'eu-west-1')._parse_rule_group({
            'Id': '99999999-8888-7777-6666-555555555555',
            'Name': 'empty',
            'ARN': 'arn:aws:wafv2:eu-west-1:123456789012:regional/rulegroup/empty/1',
            'Scope': 'REGIONAL',
        })[1]

        assert rule_group['rules_count'] == 0
        assert rule_group['blocking_rules_count'] == 0


class TestAWSWAFFacade(unittest.TestCase):

    def test_cloudfront_scope_is_only_collected_where_it_is_served(self):
        assert WAFFacade._scopes('us-east-1') == ['REGIONAL', 'CLOUDFRONT']
        assert WAFFacade._scopes('eu-west-1') == ['REGIONAL']

    def test_regional_resource_types_come_from_the_api_model(self):
        client = _StubClient([])

        types = WAFFacade._regional_resource_types(client)

        assert 'APPLICATION_LOAD_BALANCER' in types
        assert 'API_GATEWAY' in types

    def test_regional_resource_types_fall_back_on_a_known_list(self):
        types = WAFFacade._regional_resource_types(object())

        assert 'APPLICATION_LOAD_BALANCER' in types

    def test_list_all_follows_the_markers(self):
        pages = [{'WebACLs': [{'Name': 'one'}], 'NextMarker': 'one'},
                 {'WebACLs': [{'Name': 'two'}], 'NextMarker': 'two'},
                 {'WebACLs': [], 'NextMarker': 'two'}]

        results, calls = self._list_all(pages)

        assert [web_acl['Name'] for web_acl in results] == ['one', 'two']
        assert [call.get('NextMarker') for call in calls] == [None, 'one', 'two']

    def test_list_all_stops_on_a_marker_that_stopped_moving(self):
        # WAF keeps handing back the marker of the last page it sent, whether or not more is coming
        pages = [{'WebACLs': [{'Name': 'one'}], 'NextMarker': 'one'},
                 {'WebACLs': [{'Name': 'two'}], 'NextMarker': 'one'}]

        results, calls = self._list_all(pages)

        assert [web_acl['Name'] for web_acl in results] == ['one', 'two']
        assert len(calls) == 2

    def test_list_all_gives_up_on_an_error(self):
        results, calls = self._list_all([Exception('AccessDenied')])

        assert results == []
        assert len(calls) == 1

    @staticmethod
    def _list_all(pages):
        client = _StubClient(pages)
        facade = WAFFacade.__new__(WAFFacade)
        facade.session = None

        with mock.patch.object(waf_facade.AWSFacadeUtils, 'get_client', return_value=client), \
                mock.patch.object(waf_facade, 'run_concurrently', _call_directly):
            results = asyncio.run(
                facade._list_all('eu-west-1', 'list_web_acls', 'WebACLs', Scope='REGIONAL'))

        return results, client.calls


async def _call_directly(function):
    return function()


class _StubClient:
    """Answers list_web_acls with the given pages in order, recording the arguments it was called
    with. An page that is an exception is raised instead of returned."""

    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = []
        self.meta = boto3.Session(region_name='us-east-1').client(
            'wafv2', aws_access_key_id='stub', aws_secret_access_key='stub').meta

    def list_web_acls(self, **arguments):
        self.calls.append(arguments)
        page = self.pages.pop(0)
        if isinstance(page, Exception):
            raise page
        return page
