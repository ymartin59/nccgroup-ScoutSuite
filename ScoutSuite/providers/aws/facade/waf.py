from typing import Dict, List, Optional

from botocore.exceptions import ClientError

from ScoutSuite.core.console import print_exception
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently, get_and_set_concurrently

# The endpoint serving the CLOUDFRONT scope. CloudFront is global and its web ACLs are only reachable
# through this region, whichever region the distributions are served from.
CLOUDFRONT_SCOPE_REGION = 'us-east-1'

# Asking for a web ACL that does not exist, a logging configuration that was never put, or a resource
# type the region does not know about all answer with one of these rather than with an empty result
_ABSENT_ERROR_CODES = ('WAFNonexistentItemException',
                       'WAFInvalidParameterException',
                       'WAFUnavailableEntityException')


class WAFFacade(AWSBaseFacade):
    # AWS WAF is reached through the 'wafv2' boto3 client. WAF Classic ('waf' and 'waf-regional')
    # reached end of support and is not collected.

    async def get_web_acls(self, region: str) -> List[Dict]:
        """The web ACLs of a region, each described in full. The CLOUDFRONT scope has no region of its
        own, so its ACLs are reported under us-east-1, the endpoint that serves them."""

        web_acls = []
        for scope in self._scopes(region):
            summaries = await self._list_all(region, 'list_web_acls', 'WebACLs', Scope=scope)
            for summary in summaries:
                web_acl = await self._describe_web_acl(region, scope, summary)
                if web_acl:
                    web_acls.append(web_acl)

        await get_and_set_concurrently(
            [self._get_and_set_logging_configuration,
             self._get_and_set_associated_resources],
            web_acls, region=region)

        return web_acls

    async def get_rule_groups(self, region: str) -> List[Dict]:
        """The rule groups the account defines itself. Vendor managed rule groups are not listed here,
        they are only visible through the web ACLs referencing them."""

        rule_groups = []
        for scope in self._scopes(region):
            summaries = await self._list_all(region, 'list_rule_groups', 'RuleGroups', Scope=scope)
            for summary in summaries:
                rule_group = await self._describe_rule_group(region, scope, summary)
                if rule_group:
                    rule_groups.append(rule_group)

        return rule_groups

    @staticmethod
    def _scopes(region: str) -> List[str]:
        if region == CLOUDFRONT_SCOPE_REGION:
            return ['REGIONAL', 'CLOUDFRONT']
        return ['REGIONAL']

    async def _describe_web_acl(self, region: str, scope: str, summary: Dict) -> Optional[Dict]:
        """ListWebACLs only reports names and ARNs, everything that decides what an ACL does comes from
        GetWebACL."""

        client = AWSFacadeUtils.get_client('wafv2', self.session, region)
        try:
            response = await run_concurrently(
                lambda: client.get_web_acl(Name=summary['Name'], Scope=scope, Id=summary['Id']))
        except Exception as e:
            print_exception(f'Failed to describe WAF web ACL {summary.get("Name")}: {e}')
            return None

        web_acl = response.get('WebACL') or {}
        web_acl['Scope'] = scope
        return web_acl

    async def _describe_rule_group(self, region: str, scope: str, summary: Dict) -> Optional[Dict]:
        client = AWSFacadeUtils.get_client('wafv2', self.session, region)
        try:
            response = await run_concurrently(
                lambda: client.get_rule_group(Name=summary['Name'], Scope=scope, Id=summary['Id']))
        except Exception as e:
            print_exception(f'Failed to describe WAF rule group {summary.get("Name")}: {e}')
            return None

        rule_group = response.get('RuleGroup') or {}
        rule_group['Scope'] = scope
        return rule_group

    async def _get_and_set_logging_configuration(self, web_acl: Dict, region: str):
        client = AWSFacadeUtils.get_client('wafv2', self.session, region)
        try:
            response = await run_concurrently(
                lambda: client.get_logging_configuration(ResourceArn=web_acl['ARN']))
        except ClientError as e:
            # An ACL that never had logging enabled answers with WAFNonexistentItemException
            if e.response['Error']['Code'] not in _ABSENT_ERROR_CODES:
                print_exception(f'Failed to get WAF logging configuration: {e}')
            return
        except Exception as e:
            print_exception(f'Failed to get WAF logging configuration: {e}')
            return

        if response.get('LoggingConfiguration'):
            web_acl['logging_configuration'] = response['LoggingConfiguration']

    async def _get_and_set_associated_resources(self, web_acl: Dict, region: str):
        """The resources an ACL actually protects. A regional ACL is asked one resource type at a time,
        as ListResourcesForWebACL only answers for load balancers when the type is left out. A
        CloudFront ACL is not covered by that API at all and is resolved through CloudFront itself."""

        if web_acl.get('Scope') == 'CLOUDFRONT':
            web_acl['associated_resources'] = await self._get_associated_distributions(web_acl['ARN'])
            return

        client = AWSFacadeUtils.get_client('wafv2', self.session, region)
        associated_resources, answered = {}, False
        for resource_type in self._regional_resource_types(client):
            try:
                response = await run_concurrently(
                    lambda: client.list_resources_for_web_acl(
                        WebACLArn=web_acl['ARN'], ResourceType=resource_type))
            except ClientError as e:
                # A resource type the region or the partition does not serve is not an error worth
                # reporting, it simply protects nothing here
                if e.response['Error']['Code'] not in _ABSENT_ERROR_CODES:
                    print_exception(f'Failed to list resources protected by a WAF web ACL: {e}')
                    continue
                answered = True
                continue
            except Exception as e:
                print_exception(f'Failed to list resources protected by a WAF web ACL: {e}')
                continue

            answered = True
            for arn in response.get('ResourceArns') or []:
                associated_resources[arn] = resource_type

        # An ACL nothing answered for is left undecided rather than reported as protecting nothing,
        # which is what a denied ListResourcesForWebACL would otherwise look like
        web_acl['associated_resources'] = associated_resources if answered else None

    async def _get_associated_distributions(self, web_acl_arn: str) -> Optional[Dict[str, str]]:
        client = AWSFacadeUtils.get_client('cloudfront', self.session)
        distributions, marker = {}, None
        while True:
            arguments = {'WebACLId': web_acl_arn}
            if marker:
                arguments['Marker'] = marker
            try:
                response = await run_concurrently(
                    lambda: client.list_distributions_by_web_acl_id(**arguments))
            except Exception as e:
                print_exception(f'Failed to list CloudFront distributions protected by a WAF web ACL: {e}')
                return None

            distribution_list = response.get('DistributionList') or {}
            for distribution in distribution_list.get('Items') or []:
                if distribution.get('ARN'):
                    distributions[distribution['ARN']] = 'CLOUDFRONT_DISTRIBUTION'

            next_marker = distribution_list.get('NextMarker')
            if not distribution_list.get('IsTruncated') or not next_marker or next_marker == marker:
                break
            marker = next_marker

        return distributions

    @staticmethod
    def _regional_resource_types(client) -> List[str]:
        """The resource types a regional web ACL may be associated with, read from the API model so
        that types AWS adds are covered without transcribing a list that goes stale."""

        try:
            return list(client.meta.service_model.shape_for('ResourceType').enum)
        except Exception:
            return ['APPLICATION_LOAD_BALANCER', 'API_GATEWAY', 'APPSYNC', 'COGNITO_USER_POOL',
                    'APP_RUNNER_SERVICE', 'VERIFIED_ACCESS_INSTANCE', 'AMPLIFY']

    async def _list_all(self, region: str, operation: str, entity: str, **arguments) -> List[Dict]:
        """WAF has no boto3 paginator, it hands over a NextMarker to pass back on the next call."""

        client = AWSFacadeUtils.get_client('wafv2', self.session, region)
        results, marker = [], None
        while True:
            page_arguments = dict(arguments)
            if marker:
                page_arguments['NextMarker'] = marker
            try:
                response = await run_concurrently(
                    lambda: getattr(client, operation)(**page_arguments))
            except Exception as e:
                print_exception(f'Failed to call {operation} on the wafv2 service: {e}')
                break

            page = response.get(entity) or []
            results.extend(page)

            next_marker = response.get('NextMarker')
            # WAF keeps returning the marker of the last page it sent, so a marker on its own is not
            # a promise that more is coming
            if not page or not next_marker or next_marker == marker:
                break
            marker = next_marker

        return results
