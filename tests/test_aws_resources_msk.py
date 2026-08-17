import unittest

from ScoutSuite.providers.aws.facade.msk import MSKFacade
from ScoutSuite.providers.aws.resources.msk.clusters import Clusters


class TestAWSMSKServerProperties(unittest.TestCase):

    @staticmethod
    def _parse(server_properties, authentication=None):
        cluster = {
            'tls_authentication_enabled': False,
            'scram_authentication_enabled': False,
            'unauthenticated_access_enabled': False,
        }
        cluster.update(authentication or {})
        Clusters._parse_server_properties(
            {'server_properties': server_properties}, {'BrokerNodeGroupInfo': {}}, cluster)
        return cluster

    def test_properties_left_at_their_defaults(self):
        # A cluster with no configuration of its own still behaves the way MSK decided for it
        cluster = self._parse(None, {'tls_authentication_enabled': True})

        assert cluster['acl_default_allow'] is True
        assert cluster['acl_default_allow_effective'] is True
        assert cluster['auto_create_topics_enabled'] is False
        assert cluster['unclean_leader_election_enabled'] is True

    def test_properties_read_from_the_configuration(self):
        cluster = self._parse({
            'allow.everyone.if.no.acl.found': 'false',
            'auto.create.topics.enable': 'true',
            'unclean.leader.election.enable': 'false',
        }, {'scram_authentication_enabled': True})

        assert cluster['acl_default_allow'] is False
        assert cluster['acl_default_allow_effective'] is False
        assert cluster['auto_create_topics_enabled'] is True
        assert cluster['unclean_leader_election_enabled'] is False
        # Properties the configuration does not override keep their default
        assert cluster['server_properties']['allow.everyone.if.no.acl.found'] == 'false'

    def test_acl_default_is_moot_under_iam_access_control(self):
        # Kafka ACLs are not consulted for clients authenticated with SASL/IAM, so the setting that
        # governs their absence decides nothing on an IAM only cluster
        cluster = self._parse(None)

        assert cluster['acl_default_allow'] is True
        assert cluster['acl_default_allow_effective'] is False

    def test_acl_default_applies_to_unauthenticated_clients(self):
        cluster = self._parse(None, {'unauthenticated_access_enabled': True})

        assert cluster['acl_default_allow_effective'] is True

    def test_serverless_cluster_has_no_broker_configuration(self):
        cluster = {}
        Clusters._parse_server_properties({}, {}, cluster)

        assert cluster['server_properties'] == {}
        assert cluster['acl_default_allow'] is None
        assert cluster['acl_default_allow_effective'] is None
        assert cluster['auto_create_topics_enabled'] is None


class TestAWSMSKServerPropertiesParsing(unittest.TestCase):

    def test_parse_properties_file(self):
        properties = MSKFacade._parse_server_properties(
            b'# a comment\n'
            b'auto.create.topics.enable=false\n'
            b'\n'
            b'  min.insync.replicas = 2  \n'
            b'! another comment\n'
            b'log.retention.hours=168\n'
            b'not a property line\n')

        assert properties == {
            'auto.create.topics.enable': 'false',
            'min.insync.replicas': '2',
            'log.retention.hours': '168',
        }

    def test_parse_value_containing_a_separator(self):
        properties = MSKFacade._parse_server_properties(b'compression.type=producer=gzip\n')

        assert properties == {'compression.type': 'producer=gzip'}

    def test_parse_empty_properties(self):
        assert MSKFacade._parse_server_properties(None) == {}
        assert MSKFacade._parse_server_properties(b'') == {}


class TestAWSMSKAuthentication(unittest.TestCase):

    @staticmethod
    def _parse(provisioned, serverless=None, raw_cluster=None):
        cluster = {}
        Clusters._parse_authentication(
            raw_cluster or {}, provisioned, serverless or {}, cluster)
        return cluster

    def test_iam_only_cluster(self):
        cluster = self._parse({'ClientAuthentication': {'Sasl': {'Iam': {'Enabled': True},
                                                                'Scram': {'Enabled': False}},
                                                       'Unauthenticated': {'Enabled': False}}})

        assert cluster['iam_authentication_enabled'] is True
        assert cluster['unauthenticated_access_enabled'] is False
        assert cluster['authentication_methods'] == ['SASL/IAM']

    def test_cluster_created_without_client_authentication(self):
        # MSK opens such a cluster to unauthenticated clients rather than to nobody
        cluster = self._parse({'BrokerNodeGroupInfo': {}})

        assert cluster['unauthenticated_access_enabled'] is True
        assert cluster['authentication_methods'] == ['Unauthenticated']

    def test_serverless_cluster_is_iam_only(self):
        cluster = self._parse({}, {'ClientAuthentication': {'Sasl': {'Iam': {'Enabled': True}}}})

        assert cluster['iam_authentication_enabled'] is True
        assert cluster['unauthenticated_access_enabled'] is False
        assert cluster['scram_secrets_count'] is None

    def test_scram_secrets_are_counted(self):
        cluster = self._parse(
            {'ClientAuthentication': {'Sasl': {'Scram': {'Enabled': True}}}},
            raw_cluster={'scram_secrets': ['arn:aws:secretsmanager:eu-west-1:123456789012:secret:a',
                                           'arn:aws:secretsmanager:eu-west-1:123456789012:secret:b']})

        assert cluster['scram_authentication_enabled'] is True
        assert cluster['scram_secrets_count'] == 2


class TestAWSMSKEncryption(unittest.TestCase):

    @staticmethod
    def _parse_in_transit(provisioned):
        cluster = {}
        Clusters._parse_encryption_in_transit(provisioned, cluster)
        return cluster

    def test_tls_enforced(self):
        cluster = self._parse_in_transit(
            {'EncryptionInfo': {'EncryptionInTransit': {'ClientBroker': 'TLS', 'InCluster': True}}})

        assert cluster['client_broker_plaintext_allowed'] is False
        assert cluster['client_broker_plaintext_only'] is False

    def test_plaintext_allowed_alongside_tls(self):
        cluster = self._parse_in_transit(
            {'EncryptionInfo': {'EncryptionInTransit': {'ClientBroker': 'TLS_PLAINTEXT',
                                                        'InCluster': True}}})

        assert cluster['client_broker_plaintext_allowed'] is True
        assert cluster['client_broker_plaintext_only'] is False

    def test_plaintext_only(self):
        cluster = self._parse_in_transit(
            {'EncryptionInfo': {'EncryptionInTransit': {'ClientBroker': 'PLAINTEXT',
                                                        'InCluster': False}}})

        assert cluster['client_broker_plaintext_only'] is True
        assert cluster['encryption_in_cluster'] is False

    def test_serverless_cluster_is_encrypted_either_way(self):
        cluster = self._parse_in_transit({})

        assert cluster['encryption_in_transit_client_broker'] == 'TLS'
        assert cluster['client_broker_plaintext_allowed'] is False
        assert cluster['encryption_in_cluster'] is True


class TestAWSMSKConnectivity(unittest.TestCase):

    @staticmethod
    def _parse(provisioned):
        cluster = {}
        Clusters._parse_connectivity(provisioned, cluster)
        return cluster

    def test_public_access_enabled(self):
        cluster = self._parse({'BrokerNodeGroupInfo': {'ConnectivityInfo': {
            'PublicAccess': {'Type': 'SERVICE_PROVIDED_EIPS'}}}})

        assert cluster['public_access_enabled'] is True

    def test_public_access_disabled(self):
        cluster = self._parse({'BrokerNodeGroupInfo': {'ConnectivityInfo': {
            'PublicAccess': {'Type': 'DISABLED'}}}})

        assert cluster['public_access_enabled'] is False

    def test_public_access_absent_from_the_description(self):
        cluster = self._parse({'BrokerNodeGroupInfo': {}})

        assert cluster['public_access_type'] is None
        assert cluster['public_access_enabled'] is False
        assert cluster['vpc_connectivity_enabled'] is False

    def test_vpc_connectivity(self):
        cluster = self._parse({'BrokerNodeGroupInfo': {'ConnectivityInfo': {
            'VpcConnectivity': {'ClientAuthentication': {'Sasl': {'Iam': {'Enabled': True}}}}}}})

        assert cluster['vpc_connectivity_iam_enabled'] is True
        assert cluster['vpc_connectivity_enabled'] is True


class TestAWSMSKVersion(unittest.TestCase):

    @staticmethod
    def _parse(version, statuses):
        cluster = {}
        Clusters._parse_version(
            {'CurrentBrokerSoftwareInfo': {'KafkaVersion': version}} if version else {},
            cluster, statuses)
        return cluster

    def test_active_version(self):
        cluster = self._parse('3.6.0', {'3.6.0': 'ACTIVE', '2.8.1': 'DEPRECATED'})

        assert cluster['kafka_version_status'] == 'ACTIVE'
        assert cluster['kafka_version_deprecated'] is False

    def test_deprecated_version(self):
        cluster = self._parse('2.8.1', {'3.6.0': 'ACTIVE', '2.8.1': 'DEPRECATED'})

        assert cluster['kafka_version_deprecated'] is True

    def test_version_the_api_did_not_report(self):
        # Left undecided rather than assumed to be supported or not
        cluster = self._parse('3.6.0', {})

        assert cluster['kafka_version_status'] is None
        assert cluster['kafka_version_deprecated'] is None

    def test_serverless_cluster_has_no_version(self):
        cluster = self._parse(None, {'3.6.0': 'ACTIVE'})

        assert cluster['kafka_version'] is None
        assert cluster['kafka_version_deprecated'] is None


class TestAWSMSKMonitoring(unittest.TestCase):

    @staticmethod
    def _parse(provisioned):
        cluster = {}
        Clusters._parse_monitoring(provisioned, cluster)
        return cluster

    def test_logs_delivered_to_one_destination(self):
        cluster = self._parse({'LoggingInfo': {'BrokerLogs': {
            'CloudWatchLogs': {'Enabled': False},
            'Firehose': {'Enabled': False},
            'S3': {'Enabled': True, 'Bucket': 'broker-logs'}}}})

        assert cluster['broker_logs_enabled'] is True
        assert cluster['broker_logs_s3_bucket'] == 'broker-logs'

    def test_no_log_destination_enabled(self):
        cluster = self._parse({'LoggingInfo': {'BrokerLogs': {
            'CloudWatchLogs': {'Enabled': False},
            'Firehose': {'Enabled': False},
            'S3': {'Enabled': False}}}})

        assert cluster['broker_logs_enabled'] is False

    def test_logging_absent_from_the_description(self):
        cluster = self._parse({})

        assert cluster['broker_logs_enabled'] is False
        assert cluster['enhanced_monitoring'] is None
        # Nothing to report on a cluster that publishes no monitoring level, such as a serverless one
        assert cluster['enhanced_monitoring_enabled'] is None

    def test_default_monitoring_level(self):
        cluster = self._parse({'EnhancedMonitoring': 'DEFAULT'})

        assert cluster['enhanced_monitoring_enabled'] is False

    def test_per_broker_monitoring_level(self):
        cluster = self._parse({'EnhancedMonitoring': 'PER_BROKER'})

        assert cluster['enhanced_monitoring_enabled'] is True
