from typing import Dict, List, Optional

from ScoutSuite.core.console import print_exception
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently, get_and_set_concurrently, map_concurrently

# The finding types worth a call of their own. Whether an external or an internal access finding
# matters at all is decided by fields the listing does not return - the principal the resource is
# shared with, whether that principal is the whole internet, and whether a resource control policy
# already blocks the access - while an unused access finding is fully identified by the role, user or
# access key it names, which the listing already carries.
DETAILED_FINDING_TYPES = ('ExternalAccess', 'InternalAccess')

# A finding Access Analyzer has resolved describes an access path that no longer exists, so only the
# findings still standing and the ones an archive rule or an operator has put aside are collected.
COLLECTED_FINDING_STATUSES = ['ACTIVE', 'ARCHIVED']


class AccessAnalyzerFacade(AWSBaseFacade):
    async def get_analyzers(self, region: str) -> List[Dict]:
        try:
            analyzers = await AWSFacadeUtils.get_all_pages(
                'accessanalyzer', region, self.session, 'list_analyzers', 'analyzers')
        except Exception as e:
            print_exception(f'Failed to list IAM Access Analyzer analyzers: {e}')
            return []

        await get_and_set_concurrently(
            [self._get_and_set_archive_rules, self._get_and_set_findings], analyzers, region=region)

        return analyzers

    async def _get_and_set_archive_rules(self, analyzer: Dict, region: str):
        """Attach the archive rules of the analyzer. A finding an archive rule matches is created
        already archived, so the rules decide which findings anyone is ever shown."""

        try:
            analyzer['archive_rule_details'] = await AWSFacadeUtils.get_all_pages(
                'accessanalyzer', region, self.session, 'list_archive_rules', 'archiveRules',
                analyzerName=analyzer['name'])
        except Exception as e:
            print_exception(f'Failed to list the archive rules of IAM Access Analyzer analyzer '
                            f'{analyzer.get("name")}: {e}')

    async def _get_and_set_findings(self, analyzer: Dict, region: str):
        """Attach the findings of the analyzer, with the detail of those whose meaning is not in the
        listing.

        Only an analyzer that is ACTIVE is asked for findings: one still being created has analyzed
        nothing yet, and a disabled or failed one keeps whatever it held when it stopped, which
        describes the account as it was rather than as it is."""

        if analyzer.get('status') != 'ACTIVE':
            return

        try:
            findings = await AWSFacadeUtils.get_all_pages(
                'accessanalyzer', region, self.session, 'list_findings_v2', 'findings',
                analyzerArn=analyzer['arn'], filter={'status': {'eq': COLLECTED_FINDING_STATUSES}})
        except Exception as e:
            print_exception(f'Failed to list the findings of IAM Access Analyzer analyzer '
                            f'{analyzer.get("name")}: {e}')
            return

        analyzer['finding_summaries'] = findings

        # An archived finding is one somebody has already decided about, so only the findings still
        # standing are worth the extra call
        detailed = [finding for finding in findings
                    if finding.get('status') == 'ACTIVE'
                    and finding.get('findingType') in DETAILED_FINDING_TYPES]

        details = await map_concurrently(
            self._get_finding, detailed, region=region, analyzer_arn=analyzer['arn'])
        analyzer['finding_details'] = {detail['id']: detail for detail in details
                                       if detail and detail.get('id')}

    async def _get_finding(self, finding: Dict, region: str, analyzer_arn: str) -> Optional[Dict]:
        client = AWSFacadeUtils.get_client('accessanalyzer', self.session, region)
        try:
            detail = await run_concurrently(
                lambda: client.get_finding_v2(analyzerArn=analyzer_arn, id=finding['id']))
        except Exception as e:
            print_exception(f'Failed to get IAM Access Analyzer finding {finding.get("id")}: {e}')
            return None

        detail.pop('ResponseMetadata', None)
        return detail
