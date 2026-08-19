from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.regions import Regions
from ScoutSuite.providers.aws.resources.waf.rule_groups import RuleGroups
from ScoutSuite.providers.aws.resources.waf.web_acls import WebACLs


class WAF(Regions):
    _children = [
        (WebACLs, 'web_acls'),
        (RuleGroups, 'rule_groups')
    ]

    def __init__(self, facade: AWSFacade):
        # AWS WAF is exposed by boto3 as wafv2, the name waf being kept by the retired first version
        super().__init__('wafv2', facade)
