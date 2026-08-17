import unittest

from ScoutSuite.providers.aws.resources.eks.clusters import Clusters


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
