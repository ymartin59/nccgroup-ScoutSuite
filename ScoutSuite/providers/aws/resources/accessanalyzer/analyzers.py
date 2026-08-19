from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id

# What an analyzer of each type looks at. An analyzer only ever answers one of these three questions,
# so an account needs one of each to see the whole picture, and the absence of a type is the absence
# of the answer rather than a clean result.
ANALYZER_KINDS = {
    'ACCOUNT': 'EXTERNAL_ACCESS',
    'ORGANIZATION': 'EXTERNAL_ACCESS',
    'ACCOUNT_UNUSED_ACCESS': 'UNUSED_ACCESS',
    'ORGANIZATION_UNUSED_ACCESS': 'UNUSED_ACCESS',
    'ACCOUNT_INTERNAL_ACCESS': 'INTERNAL_ACCESS',
    'ORGANIZATION_INTERNAL_ACCESS': 'INTERNAL_ACCESS',
}

# The kind of analyzer each finding type comes from, which is what decides how a finding is to be read
FINDING_CATEGORIES = {
    'ExternalAccess': 'EXTERNAL_ACCESS',
    'InternalAccess': 'INTERNAL_ACCESS',
    'UnusedIAMRole': 'UNUSED_ACCESS',
    'UnusedIAMUserAccessKey': 'UNUSED_ACCESS',
    'UnusedIAMUserPassword': 'UNUSED_ACCESS',
    'UnusedPermission': 'UNUSED_ACCESS',
}

# The two detail structures that describe who reaches the resource; a finding carries one or the other
ACCESS_DETAIL_KEYS = ('externalAccessDetails', 'internalAccessDetails')

# A control policy restriction is only in force when it is APPLIED: the other values say that a policy
# exists, that it does not apply, or that Access Analyzer could not evaluate it, none of which stops
# the access the finding describes.
RESTRICTION_IN_FORCE = 'APPLIED'


class Analyzers(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw_analyzer in await self.facade.accessanalyzer.get_analyzers(self.region):
            id, analyzer = self._parse_analyzer(raw_analyzer)
            self[id] = analyzer

    def _parse_analyzer(self, raw_analyzer):
        name = raw_analyzer['name']
        analyzer_type = raw_analyzer.get('type')
        configuration = raw_analyzer.get('configuration') or {}
        unused_access = configuration.get('unusedAccess') or {}
        internal_access = configuration.get('internalAccess') or {}

        analyzer = {}
        # An analyzer has no identifier of its own. Its name is unique within the account and region and
        # is what the archive rule calls take, but a name may contain dots, which Scout's path recursion
        # cannot carry.
        analyzer['id'] = get_non_provider_id(name)
        analyzer['name'] = name
        analyzer['arn'] = raw_analyzer.get('arn')
        analyzer['region'] = self.region
        analyzer['type'] = analyzer_type
        analyzer['kind'] = ANALYZER_KINDS.get(analyzer_type)
        # The zone of trust the analyzer applies. An ORGANIZATION analyzer treats every account of the
        # organization as internal, so it reports strictly less external access than an ACCOUNT one, and
        # it only exists in the management or the delegated administrator account.
        analyzer['organization_wide'] = str(analyzer_type).startswith('ORGANIZATION')
        analyzer['status'] = raw_analyzer.get('status')
        # Why an analyzer is not usable: a failed analyzer reports the service-linked role it lost or
        # the quota it hit here, and analyses nothing until that is fixed
        analyzer['status_reason'] = (raw_analyzer.get('statusReason') or {}).get('code')
        analyzer['active'] = raw_analyzer.get('status') == 'ACTIVE'
        analyzer['creation_time'] = _format_time(raw_analyzer.get('createdAt'))
        analyzer['last_resource_analyzed'] = raw_analyzer.get('lastResourceAnalyzed')
        analyzer['last_resource_analyzed_time'] = _format_time(raw_analyzer.get('lastResourceAnalyzedAt'))
        # Set on the analyzers an AWS service creates and owns on the account's behalf, which the
        # account can neither reconfigure nor delete
        analyzer['managed_by'] = raw_analyzer.get('managedBy')
        # The tracking period after which an unused access analyzer reports a role, a password or an
        # access key as unused. AWS applies 90 days when the analyzer asks for nothing.
        analyzer['unused_access_age'] = unused_access.get('unusedAccessAge')
        # Accounts and tagged resources an unused access analyzer never reports on, which is how a role
        # stops being tracked without anybody deleting a finding
        analyzer['unused_access_exclusions'] = [
            {
                'account_ids': exclusion.get('accountIds') or [],
                'resource_tags': exclusion.get('resourceTags') or [],
            }
            for exclusion in (unused_access.get('analysisRule') or {}).get('exclusions') or []
        ]
        # An internal access analyzer only looks at what it is told to look at, so an empty inclusion
        # list is the analyzer covering every supported resource of its scope
        analyzer['internal_access_inclusions'] = [
            {
                'account_ids': inclusion.get('accountIds') or [],
                'resource_types': inclusion.get('resourceTypes') or [],
                'resource_arns': inclusion.get('resourceArns') or [],
            }
            for inclusion in (internal_access.get('analysisRule') or {}).get('inclusions') or []
        ]
        analyzer['tags'] = raw_analyzer.get('tags') or {}

        self._parse_archive_rules(raw_analyzer, analyzer)
        self._parse_findings(raw_analyzer, analyzer)

        return analyzer['id'], analyzer

    @staticmethod
    def _parse_archive_rules(raw_analyzer, analyzer):
        """The archive rules of the analyzer.

        A finding matching an archive rule is created already archived, so it never appears in the list
        an operator works through and never reaches whatever consumes the findings. The filter is an AND
        of criteria, each naming a finding field and the values it must or must not take.
        """

        rules = {}
        for raw_rule in raw_analyzer.get('archive_rule_details') or []:
            name = raw_rule.get('ruleName')
            if not name:
                continue

            criteria = [
                {
                    'key': key,
                    'equals': criterion.get('eq') or [],
                    'not_equals': criterion.get('neq') or [],
                    'contains': criterion.get('contains') or [],
                    'exists': criterion.get('exists'),
                }
                for key, criterion in (raw_rule.get('filter') or {}).items()
            ]

            rule_id = get_non_provider_id(name)
            rules[rule_id] = {
                'id': rule_id,
                'name': name,
                # The report addresses a rule through the analyzer it belongs to
                'region': analyzer['region'],
                'analyzer': analyzer['id'],
                'criteria': criteria,
                'filtered_keys': sorted(criterion['key'] for criterion in criteria),
                'archives_public_access': _archives_public_access(criteria),
                'creation_time': _format_time(raw_rule.get('createdAt')),
                'last_updated_time': _format_time(raw_rule.get('updatedAt')),
            }

        analyzer['archive_rules'] = rules
        analyzer['archive_rules_count'] = len(rules)

    def _parse_findings(self, raw_analyzer, analyzer):
        details = raw_analyzer.get('finding_details') or {}

        findings = {}
        for summary in raw_analyzer.get('finding_summaries') or []:
            finding_id = summary.get('id')
            if not finding_id:
                continue
            findings[finding_id] = self._parse_finding(summary, details.get(finding_id), analyzer)

        analyzer['access_findings'] = findings
        analyzer['access_findings_count'] = len(findings)
        # An active finding is one nobody has decided about yet: an operator who has reviewed a share
        # and accepted it archives the finding, and Access Analyzer resolves the ones whose access is
        # gone, so what is still active is what is both true and unreviewed.
        analyzer['active_findings_count'] = len([f for f in findings.values() if f['active']])
        analyzer['archived_findings_count'] = len([f for f in findings.values()
                                                  if f['status'] == 'ARCHIVED'])
        analyzer['public_access_findings_count'] = len([f for f in findings.values()
                                                       if f['active'] and f['is_public']])

    def _parse_finding(self, summary, detail, analyzer):
        finding_type = summary.get('findingType')
        resource = summary.get('resource')

        finding = {}
        finding['id'] = summary['id']
        # The finding identifier is a UUID; the resource it is about is what a reader recognises
        finding['name'] = resource or summary['id']
        # The report addresses a finding through the analyzer that raised it
        finding['region'] = analyzer['region']
        finding['analyzer'] = analyzer['id']
        finding['finding_type'] = finding_type
        finding['category'] = FINDING_CATEGORIES.get(finding_type)
        finding['resource'] = resource
        finding['resource_type'] = summary.get('resourceType')
        finding['resource_owner_account'] = summary.get('resourceOwnerAccount')
        finding['status'] = summary.get('status')
        finding['active'] = summary.get('status') == 'ACTIVE'
        finding['creation_time'] = _format_time(summary.get('createdAt'))
        finding['analyzed_time'] = _format_time(summary.get('analyzedAt'))
        finding['last_updated_time'] = _format_time(summary.get('updatedAt'))
        # Set when Access Analyzer could not evaluate the resource, in which case the finding says
        # nothing about whether that resource is shared
        finding['error'] = summary.get('error')

        self._parse_finding_access(finding, detail)

        return finding

    @staticmethod
    def _parse_finding_access(finding, detail):
        """Who reaches the resource, from the detail of the finding.

        A finding holds one detail entry per access path it found, each naming the principal, the
        actions it may take and the conditions attached. Nothing is decided for a finding whose detail
        was not read - the unused access findings, which are identified by the resource they name, and
        anything the API could not answer - so those are left unknown rather than reported as private.
        """

        finding['is_public'] = None
        finding['principals'] = []
        finding['principal_types'] = []
        finding['actions'] = []
        finding['condition_keys'] = []
        finding['sources'] = []
        finding['access_type'] = None
        finding['restricted_by_control_policy'] = None

        entries = [value for entry in (detail or {}).get('findingDetails') or []
                   for key, value in entry.items() if key in ACCESS_DETAIL_KEYS and value]
        if not entries:
            return

        principals, principal_types, actions, condition_keys, sources = set(), set(), set(), set(), set()
        for entry in entries:
            # The principal is a map from the kind of principal to its identifier: AWS for an account,
            # a role or a user, Federated for an identity provider, Service for a service principal,
            # and a bare "*" under any of them is everyone
            for principal_type, principal in (entry.get('principal') or {}).items():
                principal_types.add(principal_type)
                principals.add(principal)
            actions.update(entry.get('action') or [])
            condition_keys.update((entry.get('condition') or {}).keys())
            # Where the access comes from: the resource policy, a bucket ACL, or an S3 access point,
            # which is the same exposure reached through a different object
            sources.update(source['type'] for source in entry.get('sources') or [] if source.get('type'))

        finding['principals'] = sorted(principals)
        finding['principal_types'] = sorted(principal_types)
        finding['actions'] = sorted(actions)
        finding['condition_keys'] = sorted(condition_keys)
        finding['sources'] = sorted(sources)
        # INTRA_ACCOUNT or INTRA_ORG on an internal access finding, absent on an external access one
        finding['access_type'] = next(
            (entry['accessType'] for entry in entries if entry.get('accessType')), None)

        if finding['category'] == 'EXTERNAL_ACCESS':
            # Public means the principal is not an identity but anyone: the resource policy or the ACL
            # grants the action without naming who may take it
            finding['is_public'] = any(entry.get('isPublic') for entry in entries)

        # A resource control policy or a service control policy that is applied blocks the access the
        # finding describes, so the exposure is already contained by the organization
        finding['restricted_by_control_policy'] = all(
            entry.get('resourceControlPolicyRestriction') == RESTRICTION_IN_FORCE
            or entry.get('serviceControlPolicyRestriction') == RESTRICTION_IN_FORCE
            for entry in entries)


def _archives_public_access(criteria):
    """Whether the filter of an archive rule matches on a finding being public.

    A filter is an AND of criteria, so such a rule may well be narrowed to one resource, but whatever
    else it says, the findings it archives are findings of public access.
    """

    for criterion in criteria:
        if criterion['key'] != 'isPublic':
            continue
        # Filter values are strings, whatever the type of the field they compare
        values = [str(value).lower() for value in criterion['equals'] + criterion['contains']]
        if 'true' in values:
            return True

    return False


def _format_time(value):
    return value.strftime('%Y-%m-%d %H:%M:%S') if value else None
