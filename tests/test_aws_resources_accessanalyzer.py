import unittest
from datetime import datetime

from ScoutSuite.providers.aws.resources.accessanalyzer.analyzers import Analyzers
from ScoutSuite.providers.aws.resources.accessanalyzer.base import AccessAnalyzer
from ScoutSuite.providers.utils import get_non_provider_id


class StubFacade:
    partition = 'aws'
    owner_id = '123456789012'


def analyzers(region='eu-west-1'):
    return Analyzers(StubFacade(), region)


class TestAWSAccessAnalyzerAnalyzer(unittest.TestCase):

    @staticmethod
    def _parse(raw_analyzer):
        return analyzers()._parse_analyzer(raw_analyzer)[1]

    def test_external_access_analyzer(self):
        analyzer = self._parse({
            'name': 'account-external-access',
            'arn': 'arn:aws:access-analyzer:eu-west-1:123456789012:analyzer/account-external-access',
            'type': 'ACCOUNT',
            'status': 'ACTIVE',
            'createdAt': datetime(2023, 1, 17, 11, 42, 8),
            'lastResourceAnalyzed': 'arn:aws:s3:::reports-archive',
            'lastResourceAnalyzedAt': datetime(2023, 11, 2, 9, 14, 51),
            'tags': {'owner': 'security'},
        })

        # The name is unique per account and region, but it may contain dots, so the identifier the
        # report and the findings use is derived from it
        assert analyzer['id'] == get_non_provider_id('account-external-access')
        assert analyzer['name'] == 'account-external-access'
        assert analyzer['kind'] == 'EXTERNAL_ACCESS'
        assert analyzer['organization_wide'] is False
        assert analyzer['active'] is True
        assert analyzer['region'] == 'eu-west-1'
        assert analyzer['creation_time'] == '2023-01-17 11:42:08'
        assert analyzer['last_resource_analyzed_time'] == '2023-11-02 09:14:51'
        assert analyzer['tags'] == {'owner': 'security'}
        # An external access analyzer has no tracking period, which is an unused access setting
        assert analyzer['unused_access_age'] is None

    def test_organization_analyzer(self):
        analyzer = self._parse({'name': 'org', 'type': 'ORGANIZATION', 'status': 'ACTIVE'})

        # The whole organization is inside the zone of trust, so this analyzer reports strictly less
        # external access than an account one would
        assert analyzer['kind'] == 'EXTERNAL_ACCESS'
        assert analyzer['organization_wide'] is True

    def test_unused_access_analyzer(self):
        analyzer = self._parse({
            'name': 'unused-access',
            'type': 'ACCOUNT_UNUSED_ACCESS',
            'status': 'ACTIVE',
            'configuration': {
                'unusedAccess': {
                    'unusedAccessAge': 180,
                    'analysisRule': {
                        'exclusions': [
                            {'accountIds': ['210987654321']},
                            {'resourceTags': [{'break-glass': 'true'}]},
                        ]
                    },
                }
            },
        })

        assert analyzer['kind'] == 'UNUSED_ACCESS'
        assert analyzer['unused_access_age'] == 180
        # An exclusion stops a role being tracked without anybody deleting a finding, so what is
        # excluded is part of what the analyzer does not cover
        assert analyzer['unused_access_exclusions'] == [
            {'account_ids': ['210987654321'], 'resource_tags': []},
            {'account_ids': [], 'resource_tags': [{'break-glass': 'true'}]},
        ]

    def test_internal_access_analyzer(self):
        analyzer = self._parse({
            'name': 'internal-access',
            'type': 'ACCOUNT_INTERNAL_ACCESS',
            'status': 'ACTIVE',
            'configuration': {
                'internalAccess': {
                    'analysisRule': {
                        'inclusions': [{'resourceTypes': ['AWS::S3::Bucket']}]
                    }
                }
            },
        })

        assert analyzer['kind'] == 'INTERNAL_ACCESS'
        # An internal access analyzer only looks at what it is told to look at
        assert analyzer['internal_access_inclusions'] == [
            {'account_ids': [], 'resource_types': ['AWS::S3::Bucket'], 'resource_arns': []},
        ]

    def test_failed_analyzer(self):
        analyzer = self._parse({
            'name': 'broken',
            'type': 'ACCOUNT',
            'status': 'FAILED',
            'statusReason': {'code': 'SERVICE_LINKED_ROLE_CREATION_IN_PROGRESS'},
        })

        # It still exists and still holds its old findings, but it analyses nothing
        assert analyzer['active'] is False
        assert analyzer['status_reason'] == 'SERVICE_LINKED_ROLE_CREATION_IN_PROGRESS'

    def test_unknown_analyzer_type(self):
        # A type Access Analyzer adds later decides nothing rather than being read as one of the
        # kinds this collector knows
        analyzer = self._parse({'name': 'new', 'type': 'ACCOUNT_SOMETHING_ELSE', 'status': 'ACTIVE'})

        assert analyzer['kind'] is None


class TestAWSAccessAnalyzerArchiveRules(unittest.TestCase):

    @staticmethod
    def _parse(archive_rules):
        analyzer = {'id': 'an-analyzer', 'region': 'eu-west-1'}
        Analyzers._parse_archive_rules({'archive_rule_details': archive_rules}, analyzer)
        return analyzer

    def test_rule_archiving_public_access(self):
        analyzer = self._parse([{
            'ruleName': 'archive-public-s3',
            'filter': {
                'isPublic': {'eq': ['true']},
                'resourceType': {'eq': ['AWS::S3::Bucket']},
            },
            'createdAt': datetime(2023, 2, 3, 15, 22, 44),
        }])

        rule = analyzer['archive_rules'][get_non_provider_id('archive-public-s3')]
        assert analyzer['archive_rules_count'] == 1
        assert rule['name'] == 'archive-public-s3'
        assert rule['filtered_keys'] == ['isPublic', 'resourceType']
        assert rule['creation_time'] == '2023-02-03 15:22:44'
        # Whatever else the filter narrows the rule to, the findings it archives are findings of
        # public access
        assert rule['archives_public_access'] is True

    def test_rule_accepting_a_named_account(self):
        analyzer = self._parse([{
            'ruleName': 'accept-partner-account',
            'filter': {'principal.AWS': {'eq': ['210987654321']}},
        }])

        rule = analyzer['archive_rules'][get_non_provider_id('accept-partner-account')]
        # This is what an archive rule is for: accepting a share that has been reviewed
        assert rule['archives_public_access'] is False
        assert rule['criteria'] == [{
            'key': 'principal.AWS',
            'equals': ['210987654321'],
            'not_equals': [],
            'contains': [],
            'exists': None,
        }]

    def test_rule_excluding_public_access(self):
        # A rule that archives everything that is *not* public leaves the public findings alone
        analyzer = self._parse([{
            'ruleName': 'archive-private',
            'filter': {'isPublic': {'neq': ['true']}},
        }])

        rule = analyzer['archive_rules'][get_non_provider_id('archive-private')]
        assert rule['archives_public_access'] is False

    def test_analyzer_without_archive_rules(self):
        analyzer = self._parse(None)

        assert analyzer['archive_rules'] == {}
        assert analyzer['archive_rules_count'] == 0


class TestAWSAccessAnalyzerFindings(unittest.TestCase):

    @staticmethod
    def _parse(summaries, details=None):
        analyzer = {'id': 'an-analyzer', 'region': 'eu-west-1'}
        analyzers()._parse_findings(
            {'finding_summaries': summaries, 'finding_details': details or {}}, analyzer)
        return analyzer

    def test_public_external_access_finding(self):
        analyzer = self._parse(
            [{
                'id': 'finding-1',
                'findingType': 'ExternalAccess',
                'resource': 'arn:aws:s3:::reports-archive',
                'resourceType': 'AWS::S3::Bucket',
                'resourceOwnerAccount': '123456789012',
                'status': 'ACTIVE',
                'createdAt': datetime(2023, 10, 30, 21, 3, 12),
                'analyzedAt': datetime(2023, 11, 2, 9, 14, 51),
            }],
            {'finding-1': {'findingDetails': [{'externalAccessDetails': {
                'isPublic': True,
                'action': ['s3:GetObject', 's3:ListBucket'],
                'principal': {'AWS': '*'},
                'condition': {'aws:SourceIp': '0.0.0.0/0'},
                'sources': [{'type': 'POLICY'}],
            }}]}})

        finding = analyzer['access_findings']['finding-1']
        assert finding['category'] == 'EXTERNAL_ACCESS'
        assert finding['is_public'] is True
        assert finding['principals'] == ['*']
        assert finding['principal_types'] == ['AWS']
        assert finding['actions'] == ['s3:GetObject', 's3:ListBucket']
        assert finding['condition_keys'] == ['aws:SourceIp']
        assert finding['sources'] == ['POLICY']
        assert finding['restricted_by_control_policy'] is False
        assert finding['analyzer'] == 'an-analyzer'
        assert finding['creation_time'] == '2023-10-30 21:03:12'
        assert analyzer['active_findings_count'] == 1
        assert analyzer['public_access_findings_count'] == 1

    def test_cross_account_external_access_finding(self):
        analyzer = self._parse(
            [{'id': 'finding-2', 'findingType': 'ExternalAccess', 'status': 'ACTIVE',
              'resource': 'arn:aws:kms:eu-west-1:123456789012:key/abcd1234',
              'resourceType': 'AWS::KMS::Key'}],
            {'finding-2': {'findingDetails': [{'externalAccessDetails': {
                'isPublic': False,
                'action': ['kms:Decrypt'],
                'principal': {'AWS': 'arn:aws:iam::210987654321:root'},
                'sources': [{'type': 'POLICY'}],
            }}]}})

        finding = analyzer['access_findings']['finding-2']
        assert finding['is_public'] is False
        assert finding['principals'] == ['arn:aws:iam::210987654321:root']
        assert analyzer['public_access_findings_count'] == 0

    def test_finding_restricted_by_a_control_policy(self):
        # The policy grants the access but a resource control policy blocks it, so the exposure is
        # already contained
        analyzer = self._parse(
            [{'id': 'finding-3', 'findingType': 'ExternalAccess', 'status': 'ACTIVE',
              'resource': 'arn:aws:s3:::legacy-public-assets', 'resourceType': 'AWS::S3::Bucket'}],
            {'finding-3': {'findingDetails': [{'externalAccessDetails': {
                'isPublic': True,
                'principal': {'AWS': '*'},
                'resourceControlPolicyRestriction': 'APPLIED',
            }}]}})

        assert analyzer['access_findings']['finding-3']['restricted_by_control_policy'] is True

    def test_finding_a_control_policy_only_could_restrict(self):
        # A policy that exists but does not restrict this access leaves the finding standing
        analyzer = self._parse(
            [{'id': 'finding-4', 'findingType': 'ExternalAccess', 'status': 'ACTIVE',
              'resource': 'arn:aws:s3:::reports-archive', 'resourceType': 'AWS::S3::Bucket'}],
            {'finding-4': {'findingDetails': [{'externalAccessDetails': {
                'isPublic': True,
                'principal': {'AWS': '*'},
                'resourceControlPolicyRestriction': 'APPLICABLE',
            }}]}})

        assert analyzer['access_findings']['finding-4']['restricted_by_control_policy'] is False

    def test_finding_with_several_access_paths(self):
        # One detail entry per access path found; the resource is public if any of them is
        analyzer = self._parse(
            [{'id': 'finding-5', 'findingType': 'ExternalAccess', 'status': 'ACTIVE',
              'resource': 'arn:aws:s3:::mixed', 'resourceType': 'AWS::S3::Bucket'}],
            {'finding-5': {'findingDetails': [
                {'externalAccessDetails': {
                    'isPublic': False,
                    'principal': {'AWS': '210987654321'},
                    'action': ['s3:GetObject'],
                    'resourceControlPolicyRestriction': 'APPLIED',
                }},
                {'externalAccessDetails': {
                    'isPublic': True,
                    'principal': {'AWS': '*'},
                    'action': ['s3:ListBucket'],
                    'sources': [{'type': 'BUCKET_ACL'}],
                }},
            ]}})

        finding = analyzer['access_findings']['finding-5']
        assert finding['is_public'] is True
        assert finding['principals'] == ['*', '210987654321']
        assert finding['actions'] == ['s3:GetObject', 's3:ListBucket']
        # Only one of the two paths is blocked, so the finding is not contained
        assert finding['restricted_by_control_policy'] is False

    def test_internal_access_finding(self):
        analyzer = self._parse(
            [{'id': 'finding-6', 'findingType': 'InternalAccess', 'status': 'ACTIVE',
              'resource': 'arn:aws:s3:::payroll', 'resourceType': 'AWS::S3::Bucket'}],
            {'finding-6': {'findingDetails': [{'internalAccessDetails': {
                'accessType': 'INTRA_ORG',
                'principal': {'AWS': 'arn:aws:iam::123456789012:role/analyst'},
                'principalType': 'IAM_ROLE',
                'action': ['s3:GetObject'],
            }}]}})

        finding = analyzer['access_findings']['finding-6']
        assert finding['category'] == 'INTERNAL_ACCESS'
        assert finding['access_type'] == 'INTRA_ORG'
        # Public is not a concept for an internal access finding, so nothing is claimed about it
        assert finding['is_public'] is None

    def test_unused_access_findings(self):
        # The listing identifies these fully, so no detail is read for them and their access fields
        # stay unknown rather than being reported as private
        analyzer = self._parse([
            {'id': 'finding-7', 'findingType': 'UnusedIAMRole', 'status': 'ACTIVE',
             'resource': 'arn:aws:iam::123456789012:role/decommissioned-batch',
             'resourceType': 'AWS::IAM::Role'},
            {'id': 'finding-8', 'findingType': 'UnusedPermission', 'status': 'ARCHIVED',
             'resource': 'arn:aws:iam::123456789012:role/report-generator',
             'resourceType': 'AWS::IAM::Role'},
        ])

        role = analyzer['access_findings']['finding-7']
        assert role['category'] == 'UNUSED_ACCESS'
        assert role['is_public'] is None
        assert role['principals'] == []
        assert role['active'] is True
        assert analyzer['access_findings']['finding-8']['active'] is False
        assert analyzer['access_findings_count'] == 2
        assert analyzer['active_findings_count'] == 1
        assert analyzer['archived_findings_count'] == 1

    def test_finding_that_could_not_be_analysed(self):
        # An error means the resource was not evaluated, so it is neither known to be shared nor
        # known to be private
        analyzer = self._parse([{
            'id': 'finding-9',
            'findingType': 'ExternalAccess',
            'status': 'ACTIVE',
            'resource': 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:legacy-Ab12Cd',
            'resourceType': 'AWS::SecretsManager::Secret',
            'error': 'ACCESS_DENIED',
        }])

        finding = analyzer['access_findings']['finding-9']
        assert finding['error'] == 'ACCESS_DENIED'
        assert finding['is_public'] is None
        assert finding['restricted_by_control_policy'] is None

    def test_analyzer_without_findings(self):
        analyzer = self._parse(None)

        assert analyzer['access_findings'] == {}
        assert analyzer['access_findings_count'] == 0
        assert analyzer['active_findings_count'] == 0
        assert analyzer['public_access_findings_count'] == 0


class TestAWSAccessAnalyzerCoverage(unittest.TestCase):
    """The counters that say whether a region is analysed at all, which is what a rule fires on when
    there is no analyzer to attach a finding to."""

    @staticmethod
    def _coverage(regions):
        service = AccessAnalyzer.__new__(AccessAnalyzer)
        dict.__init__(service)
        service['regions'] = regions
        service._set_coverage()
        return service

    @staticmethod
    def _analyzer(kind, active, active_findings=0, public_findings=0, archived_findings=0):
        return {
            'kind': kind,
            'active': active,
            'active_findings_count': active_findings,
            'archived_findings_count': archived_findings,
            'public_access_findings_count': public_findings,
        }

    def test_region_with_both_kinds_of_analyzer(self):
        service = self._coverage({'eu-west-1': {'analyzers': {
            'a': self._analyzer('EXTERNAL_ACCESS', True, active_findings=3, public_findings=1),
            'b': self._analyzer('UNUSED_ACCESS', True, active_findings=2, archived_findings=1),
        }}})

        region = service['regions']['eu-west-1']
        assert region['active_external_access_analyzers_count'] == 1
        assert region['active_unused_access_analyzers_count'] == 1
        assert region['active_findings_count'] == 5
        assert region['archived_findings_count'] == 1
        assert region['public_access_findings_count'] == 1
        assert service['active_external_access_analyzers_count'] == 1
        assert service['active_findings_count'] == 5

    def test_region_whose_only_analyzer_is_not_running(self):
        # An analyzer that is not active is not coverage, so the region counts as unanalysed
        service = self._coverage({'us-east-1': {'analyzers': {
            'a': self._analyzer('EXTERNAL_ACCESS', False),
        }}})

        region = service['regions']['us-east-1']
        assert region['external_access_analyzers_count'] == 1
        assert region['active_external_access_analyzers_count'] == 0

    def test_region_without_any_analyzer(self):
        service = self._coverage({'eu-central-1': {'analyzers': {}}})

        region = service['regions']['eu-central-1']
        assert region['active_external_access_analyzers_count'] == 0
        assert region['active_unused_access_analyzers_count'] == 0
        assert region['active_internal_access_analyzers_count'] == 0
        assert service['active_external_access_analyzers_count'] == 0

    def test_account_totals_across_regions(self):
        service = self._coverage({
            'eu-west-1': {'analyzers': {'a': self._analyzer('EXTERNAL_ACCESS', True,
                                                            active_findings=1)}},
            'us-east-1': {'analyzers': {'b': self._analyzer('EXTERNAL_ACCESS', True,
                                                            active_findings=4)}},
        })

        assert service['external_access_analyzers_count'] == 2
        assert service['active_findings_count'] == 5
