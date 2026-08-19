from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.accessanalyzer.analyzers import Analyzers
from ScoutSuite.providers.aws.resources.regions import Regions

# The per-region and account-wide counter each kind of analyzer is summed into
ANALYZER_COUNTERS = {
    'EXTERNAL_ACCESS': 'external_access_analyzers',
    'UNUSED_ACCESS': 'unused_access_analyzers',
    'INTERNAL_ACCESS': 'internal_access_analyzers',
}


class AccessAnalyzer(Regions):
    _children = [
        (Analyzers, 'analyzers')
    ]

    def __init__(self, facade: AWSFacade):
        super().__init__('accessanalyzer', facade)

    async def fetch_all(self, regions=None, excluded_regions=None, partition_name='aws', **kwargs):
        await super().fetch_all(regions, excluded_regions, partition_name, **kwargs)
        self._set_coverage()

    def _set_coverage(self):
        """Count, per region and for the account, the analyzers of each kind and how many of them are
        running.

        Whether an account looks at all for what it shares outside itself is a property of the region
        rather than of any analyzer in it, and an analyzer cannot see its siblings while they are all
        being fetched, so the counters a rule needs in order to fire on an absence are derived once the
        regions are complete.
        """

        finding_counters = ['active_findings_count', 'archived_findings_count',
                            'public_access_findings_count']
        totals = {key: 0 for key in finding_counters}
        for counter in ANALYZER_COUNTERS.values():
            totals[f'{counter}_count'] = 0
            totals[f'active_{counter}_count'] = 0

        for region in self['regions'].values():
            analyzers = list(region['analyzers'].values())

            for kind, counter in ANALYZER_COUNTERS.items():
                of_kind = [analyzer for analyzer in analyzers if analyzer['kind'] == kind]
                counts = {
                    f'{counter}_count': len(of_kind),
                    # An analyzer that is not active produces no finding, so only the active ones are
                    # coverage
                    f'active_{counter}_count': len([a for a in of_kind if a['active']]),
                }
                for key, value in counts.items():
                    region[key] = value
                    totals[key] += value

            for key in finding_counters:
                region[key] = sum(analyzer[key] for analyzer in analyzers)
                totals[key] += region[key]

        for key, value in totals.items():
            self[key] = value
