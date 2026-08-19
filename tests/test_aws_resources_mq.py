import base64
import unittest
from datetime import datetime

from ScoutSuite.providers.aws.facade.mq import MQFacade
from ScoutSuite.providers.aws.resources.mq.brokers import Brokers

# An ActiveMQ configuration as Amazon MQ returns it, namespace included
ACTIVEMQ_CONFIGURATION_WITH_MAP = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<broker xmlns="http://activemq.apache.org/schema/core">
  <plugins>
    <forcePersistencyModeBrokerPlugin persistenceFlag="true"/>
    <statisticsBrokerPlugin/>
    <authorizationPlugin>
      <map>
        <authorizationMap>
          <authorizationEntries>
            <authorizationEntry queue="orders.&gt;" read="orders-consumers"
                                write="orders-producers" admin="admins"/>
            <authorizationEntry topic="events.&gt;" read="everyone" write="publishers" admin="admins"/>
            <tempDestinationAuthorizationEntry>
              <tempDestinationAuthorizationEntry read="admins" write="admins" admin="admins"/>
            </tempDestinationAuthorizationEntry>
          </authorizationEntries>
        </authorizationMap>
      </map>
    </authorizationPlugin>
  </plugins>
</broker>
"""

ACTIVEMQ_CONFIGURATION_WITHOUT_MAP = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<broker xmlns="http://activemq.apache.org/schema/core">
  <plugins>
    <statisticsBrokerPlugin/>
    <timeStampingBrokerPlugin ttlCeiling="86400000" zeroExpirationOverride="86400000"/>
  </plugins>
</broker>
"""


class TestAWSMQAuthorizationMap(unittest.TestCase):

    @staticmethod
    def _parse(configuration_data, engine_type='ACTIVEMQ'):
        broker = {'name': 'a-broker', 'engine_type': engine_type}
        raw_broker = {'configuration_data': configuration_data} if configuration_data else {}
        Brokers._parse_authorization_map(raw_broker, broker)
        return broker

    def test_authorization_map_read_from_the_configuration(self):
        broker = self._parse(ACTIVEMQ_CONFIGURATION_WITH_MAP)

        assert broker['authorization_map_configured'] is True
        # The entries of the map, with the destination named by whichever attribute carries it. The
        # temporary destination entries are a different element and are not part of them.
        assert len(broker['authorization_entries']) == 2
        assert broker['authorization_entries'][0] == {
            'destination': 'orders.>',
            'destination_type': 'queue',
            'read': 'orders-consumers',
            'write': 'orders-producers',
            'admin': 'admins',
        }
        assert broker['authorization_entries'][1]['destination_type'] == 'topic'

    def test_configuration_without_an_authorization_plugin(self):
        # ActiveMQ consults no map unless the plugin declares one, so this broker lets any
        # authenticated user do anything
        broker = self._parse(ACTIVEMQ_CONFIGURATION_WITHOUT_MAP)

        assert broker['authorization_map_configured'] is False
        assert broker['authorization_entries'] == []

    def test_rabbitmq_broker_decides_nothing(self):
        # RabbitMQ permissions live inside the broker, where the API cannot see them
        broker = self._parse('consumer_timeout = 1800000', engine_type='RABBITMQ')

        assert broker['authorization_map_configured'] is None
        assert broker['authorization_entries'] == []

    def test_configuration_that_could_not_be_read(self):
        # A broker with no configuration attached is not a broker without a map
        broker = self._parse(None)

        assert broker['authorization_map_configured'] is None

    def test_malformed_configuration(self):
        broker = self._parse('<broker><plugins></broker>')

        assert broker['authorization_map_configured'] is None
        assert broker['authorization_entries'] == []


class TestAWSMQEngineVersion(unittest.TestCase):

    @staticmethod
    def _parse(version, supported_versions, auto_minor_version_upgrade=True):
        broker = {}
        Brokers._parse_version(
            {'EngineVersion': version, 'AutoMinorVersionUpgrade': auto_minor_version_upgrade},
            broker, supported_versions)
        return broker

    def test_supported_version(self):
        broker = self._parse('5.18.4', ['5.18.4', '5.17.6'])

        assert broker['engine_version_supported'] is True
        assert broker['engine_version_deprecated'] is False

    def test_earlier_patch_of_a_supported_line(self):
        # Amazon MQ only offers the patch it maintains for each line, so a broker behind on patches
        # is not a broker whose version line was retired
        broker = self._parse('5.18.2', ['5.18.4', '5.17.6'])

        assert broker['engine_version_supported'] is True
        assert broker['engine_version_deprecated'] is False

    def test_retired_version_line(self):
        broker = self._parse('5.15.16', ['5.18.4', '5.17.6'])

        assert broker['engine_version_supported'] is False
        assert broker['engine_version_deprecated'] is True

    def test_versions_the_api_did_not_report(self):
        # Nothing to compare against, so nothing is decided rather than everything flagged
        broker = self._parse('3.11.20', [])

        assert broker['engine_version_supported'] is None
        assert broker['engine_version_deprecated'] is None
        assert broker['supported_engine_versions'] == []

    def test_two_component_version(self):
        broker = self._parse('3.13', ['3.13', '3.12.13'])

        assert broker['engine_version_deprecated'] is False

    def test_minor_version_upgrade(self):
        assert self._parse('5.18.4', [], auto_minor_version_upgrade=False)[
            'auto_minor_version_upgrade'] is False
        assert self._parse('5.18.4', [])['auto_minor_version_upgrade'] is True


class TestAWSMQEncryption(unittest.TestCase):

    @staticmethod
    def _parse(encryption_options):
        broker = {}
        raw_broker = {'EncryptionOptions': encryption_options} if encryption_options is not None else {}
        Brokers._parse_encryption(raw_broker, broker)
        return broker

    def test_customer_managed_key(self):
        broker = self._parse({
            'KmsKeyId': 'arn:aws:kms:eu-west-1:123456789012:key/abcd1234',
            'UseAwsOwnedKey': False,
        })

        assert broker['encryption_with_cmk'] is True
        assert broker['encryption_with_aws_owned_key'] is False
        assert broker['encryption_kms_key'] == 'arn:aws:kms:eu-west-1:123456789012:key/abcd1234'

    def test_aws_owned_key(self):
        broker = self._parse({'UseAwsOwnedKey': True})

        assert broker['encryption_with_cmk'] is False
        assert broker['encryption_kms_key'] is None

    def test_broker_created_without_encryption_options(self):
        # Amazon MQ falls back on a key AWS owns, which is what the absent block means
        broker = self._parse(None)

        assert broker['encryption_with_aws_owned_key'] is True
        assert broker['encryption_with_cmk'] is False


class TestAWSMQAuthentication(unittest.TestCase):

    @staticmethod
    def _parse(raw_broker):
        broker = {}
        Brokers._parse_authentication(raw_broker, broker)
        return broker

    def test_broker_local_users(self):
        broker = self._parse({'AuthenticationStrategy': 'SIMPLE'})

        assert broker['broker_local_credentials'] is True

    def test_strategy_absent_from_the_description(self):
        # SIMPLE is what Amazon MQ applies when the creation request said nothing
        broker = self._parse({})

        assert broker['authentication_strategy'] is None
        assert broker['broker_local_credentials'] is True

    def test_ldap_directory(self):
        broker = self._parse({
            'AuthenticationStrategy': 'LDAP',
            'LdapServerMetadata': {
                'Hosts': ['ldaps.corp.example.com'],
                'ServiceAccountUsername': 'cn=amazonmq,ou=services,dc=example,dc=com',
                'UserBase': 'ou=people,dc=example,dc=com',
                'RoleBase': 'ou=groups,dc=example,dc=com',
            },
        })

        assert broker['broker_local_credentials'] is False
        assert broker['ldap_hosts'] == ['ldaps.corp.example.com']
        assert broker['ldap_role_base'] == 'ou=groups,dc=example,dc=com'

    def test_backends_declared_in_the_configuration(self):
        # How a RabbitMQ broker is pointed at OAuth 2.0, IAM, LDAP, HTTP or client certificates
        broker = self._parse({'AuthenticationStrategy': 'CONFIG_MANAGED'})

        assert broker['broker_local_credentials'] is False

    def test_pending_strategy(self):
        broker = self._parse({'AuthenticationStrategy': 'SIMPLE',
                              'PendingAuthenticationStrategy': 'LDAP'})

        assert broker['pending_authentication_strategy'] == 'LDAP'
        # The directory only authenticates anyone once the broker is rebooted
        assert broker['broker_local_credentials'] is True


class TestAWSMQUsers(unittest.TestCase):

    @staticmethod
    def _parse(raw_broker):
        broker = {}
        Brokers._parse_users(raw_broker, broker)
        return broker

    def test_users_with_their_details(self):
        broker = self._parse({
            'Users': [{'Username': 'integration-app'}, {'Username': 'metrics-reader'}],
            'user_details': [
                {'Username': 'integration-app', 'ConsoleAccess': True,
                 'Groups': ['activemq-webconsole'], 'ReplicationUser': False},
                {'Username': 'metrics-reader', 'ConsoleAccess': False, 'Groups': ['readers']},
            ],
        })

        assert broker['users_count'] == 2
        assert broker['users_with_console_access'] == ['integration-app']
        users = {user['username']: user for user in broker['users'].values()}
        assert users['integration-app']['console_access'] is True
        assert users['integration-app']['groups'] == ['activemq-webconsole']
        assert users['metrics-reader']['console_access'] is False

    def test_user_whose_details_are_not_available(self):
        # A RabbitMQ broker names its administrator but the user API does not describe it, so the
        # console access is unknown rather than absent
        broker = self._parse({'Users': [{'Username': 'admin'}]})

        user = list(broker['users'].values())[0]
        assert user['console_access'] is None
        assert user['groups'] == []
        assert broker['users_with_console_access'] == []

    def test_pending_user_change(self):
        broker = self._parse({'Users': [{'Username': 'admin', 'PendingChange': 'UPDATE'}]})

        assert list(broker['users'].values())[0]['pending_change'] == 'UPDATE'

    def test_broker_without_users(self):
        broker = self._parse({})

        assert broker['users'] == {}
        assert broker['users_count'] == 0


class TestAWSMQLogs(unittest.TestCase):

    @staticmethod
    def _parse(logs):
        broker = {}
        Brokers._parse_logs({'Logs': logs}, broker)
        return broker

    def test_both_log_streams_delivered(self):
        broker = self._parse({
            'General': True,
            'GeneralLogGroup': '/aws/amazonmq/broker/b-1/general',
            'Audit': True,
            'AuditLogGroup': '/aws/amazonmq/broker/b-1/audit',
        })

        assert broker['general_logs_enabled'] is True
        assert broker['audit_logs_enabled'] is True
        assert broker['audit_log_group'] == '/aws/amazonmq/broker/b-1/audit'

    def test_audit_logging_off(self):
        broker = self._parse({'General': True, 'GeneralLogGroup': '/aws/amazonmq/broker/b-1/general'})

        assert broker['general_logs_enabled'] is True
        assert broker['audit_logs_enabled'] is False
        assert broker['audit_log_group'] is None

    def test_logging_waiting_for_a_reboot(self):
        broker = self._parse({'General': False, 'Audit': False,
                              'Pending': {'General': True, 'Audit': True}})

        assert broker['general_logs_enabled'] is False
        assert broker['general_logs_pending'] is True
        assert broker['audit_logs_pending'] is True

    def test_no_logs_block(self):
        broker = self._parse(None)

        assert broker['general_logs_enabled'] is False
        assert broker['audit_logs_enabled'] is False


class TestAWSMQNetwork(unittest.TestCase):

    @staticmethod
    def _parse(raw_broker):
        broker = {}
        Brokers._parse_network(raw_broker, broker)
        return broker

    def test_private_broker(self):
        broker = self._parse({
            'SubnetIds': ['subnet-0a1b2c3d', 'subnet-0b2c3d4e'],
            'SecurityGroups': ['sg-0a1b2c3d'],
            'BrokerInstances': [
                {'ConsoleURL': 'https://b-1-1.mq.eu-west-1.amazonaws.com:8162',
                 'Endpoints': ['ssl://b-1-1.mq.eu-west-1.amazonaws.com:61617',
                               'amqp+ssl://b-1-1.mq.eu-west-1.amazonaws.com:5671'],
                 'IpAddress': '10.0.1.14'},
            ],
        })

        assert broker['publicly_accessible'] is False
        assert broker['subnets'] == ['subnet-0a1b2c3d', 'subnet-0b2c3d4e']
        assert len(broker['endpoints']) == 2
        assert broker['console_urls'] == ['https://b-1-1.mq.eu-west-1.amazonaws.com:8162']
        assert broker['ip_addresses'] == ['10.0.1.14']

    def test_public_broker(self):
        broker = self._parse({'PubliclyAccessible': True})

        assert broker['publicly_accessible'] is True
        assert broker['endpoints'] == []

    def test_security_groups_waiting_for_a_reboot(self):
        broker = self._parse({'SecurityGroups': ['sg-0a1b2c3d'],
                              'PendingSecurityGroups': ['sg-0b2c3d4e']})

        assert broker['security_groups'] == ['sg-0a1b2c3d']
        assert broker['pending_security_groups'] == ['sg-0b2c3d4e']


class TestAWSMQBroker(unittest.TestCase):

    @staticmethod
    def _parse(raw_broker, supported_engine_versions=None):
        return Brokers(None, 'eu-west-1')._parse_broker(
            raw_broker, supported_engine_versions or [])

    def test_broker_is_keyed_by_its_broker_id(self):
        id, broker = self._parse({
            'BrokerId': 'b-1111aaaa-11bb-22cc-33dd-444455556666',
            'BrokerName': 'orders-prod',
            'EngineType': 'ACTIVEMQ',
            'Created': datetime(2023, 4, 11, 8, 12, 3),
            'ActionsRequired': [{'ActionRequiredCode': 'BROKER_OOM'}],
            'Configurations': {'Current': {'Id': 'c-1111aaaa', 'Revision': 7},
                               'Pending': {'Id': 'c-1111aaaa', 'Revision': 8}},
        })

        assert id == 'b-1111aaaa-11bb-22cc-33dd-444455556666'
        assert broker['id'] == id
        assert broker['region'] == 'eu-west-1'
        assert broker['creation_time'] == '2023-04-11 08:12:03'
        assert broker['actions_required'] == ['BROKER_OOM']
        assert broker['configuration_revision'] == 7
        assert broker['pending_configuration_revision'] == 8

    def test_broker_without_a_configuration(self):
        id, broker = self._parse({'BrokerId': 'b-1', 'EngineType': 'RABBITMQ'})

        assert broker['configuration_id'] is None
        assert broker['authorization_map_configured'] is None


class TestAWSMQConfigurationData(unittest.TestCase):

    def test_revision_is_base64_encoded(self):
        data = base64.b64encode(ACTIVEMQ_CONFIGURATION_WITH_MAP.encode('utf-8'))

        assert MQFacade._decode_configuration_data(data) == ACTIVEMQ_CONFIGURATION_WITH_MAP

    def test_empty_revision(self):
        assert MQFacade._decode_configuration_data(None) is None
        assert MQFacade._decode_configuration_data('') is None
