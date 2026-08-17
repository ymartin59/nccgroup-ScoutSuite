import unittest
import freezegun

from ScoutSuite.providers.aws.resources.eks.clusters import Clusters


@freezegun.freeze_time("2024-01-01")
class TestAWSEKSClusterVersionSupport(unittest.TestCase):

    def _parse_version_support(self, version, raw_cluster=None):
        cluster = {'version': version}
        Clusters._parse_version_support(Clusters(None, 'eu-west-1'), raw_cluster or {}, cluster)
        return cluster

    def test_version_still_under_standard_support(self):
        cluster = self._parse_version_support('1.28')

        assert cluster['version_unsupported'] is False
        assert cluster['version_end_of_standard_support'] == '2024-11-26'

    def test_version_past_end_of_standard_support(self):
        cluster = self._parse_version_support('1.22')

        assert cluster['version_unsupported'] is True
        assert cluster['version_end_of_standard_support'] == '2023-06-04'

    def test_version_older_than_the_table(self):
        # No date is transcribed for those versions, they went out of support well before the oldest
        cluster = self._parse_version_support('1.19')

        assert cluster['version_unsupported'] is True
        assert cluster['version_end_of_standard_support'] is None

    def test_version_newer_than_the_table(self):
        cluster = self._parse_version_support('1.42')

        assert cluster['version_unsupported'] is False
        assert cluster['version_end_of_standard_support'] is None

    def test_support_type(self):
        cluster = self._parse_version_support('1.22', {'upgradePolicy': {'supportType': 'EXTENDED'}})

        assert cluster['upgrade_support_type'] == 'EXTENDED'
        assert self._parse_version_support('1.22')['upgrade_support_type'] is None


class TestAWSEKSClusters(unittest.TestCase):

    @staticmethod
    def _parse_logging(cluster_logging):
        cluster = {}
        Clusters._parse_logging({'logging': {'clusterLogging': cluster_logging}}, cluster)
        return cluster

    def test_logging_all_types_enabled(self):
        # describe_cluster returns one entry holding every enabled type, and one holding the rest
        cluster = self._parse_logging([
            {'types': ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'], 'enabled': True},
        ])

        assert cluster['logging'] is True
        assert cluster['logging_disabled_types'] == []
        assert cluster['type_logging_audit'] is True
        assert cluster['type_logging_controllerManager'] is True

    def test_logging_partially_enabled(self):
        cluster = self._parse_logging([
            {'types': ['api', 'authenticator'], 'enabled': True},
            {'types': ['audit', 'controllerManager', 'scheduler'], 'enabled': False},
        ])

        assert cluster['logging'] is True
        assert cluster['logging_enabled_types'] == ['api', 'authenticator']
        assert cluster['logging_disabled_types'] == ['audit', 'controllerManager', 'scheduler']
        assert cluster['type_logging_api'] is True
        assert cluster['type_logging_audit'] is False

    def test_logging_disabled_group_listed_first(self):
        # The order of the entries carries no meaning, so the enabled ones have to be looked for
        cluster = self._parse_logging([
            {'types': ['api', 'authenticator'], 'enabled': False},
            {'types': ['audit', 'controllerManager', 'scheduler'], 'enabled': True},
        ])

        assert cluster['logging'] is True
        assert cluster['type_logging_api'] is False
        assert cluster['type_logging_audit'] is True

    def test_logging_fully_disabled(self):
        cluster = self._parse_logging([
            {'types': ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'], 'enabled': False},
        ])

        assert cluster['logging'] is False
        assert cluster['logging_enabled_types'] == []
        assert len(cluster['logging_disabled_types']) == 5

    def test_logging_absent_from_the_description(self):
        cluster = {}
        Clusters._parse_logging({}, cluster)

        assert cluster['logging'] is False
        assert len(cluster['logging_disabled_types']) == 5
