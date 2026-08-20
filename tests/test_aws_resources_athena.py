import unittest
from datetime import datetime

from ScoutSuite.providers.aws.resources.athena.data_catalogs import DataCatalogs
from ScoutSuite.providers.aws.resources.athena.work_groups import WorkGroups


class TestAWSAthenaWorkGroupEnforcement(unittest.TestCase):

    @staticmethod
    def _parse(configuration):
        work_group = {}
        WorkGroups._parse_enforcement(configuration, work_group)
        return work_group

    def test_configuration_enforced(self):
        work_group = self._parse({
            'EnforceWorkGroupConfiguration': True,
            'EnableMinimumEncryptionConfiguration': True,
        })

        assert work_group['enforce_workgroup_configuration'] is True
        assert work_group['minimum_encryption_enforced'] is True

    def test_enforcement_absent_from_the_configuration(self):
        # Athena leaves the enforcement off when a workgroup is created through the API without
        # saying otherwise, so the absence of the flag is the permissive case and not an unknown one
        work_group = self._parse({})

        assert work_group['enforce_workgroup_configuration'] is False
        assert work_group['minimum_encryption_enforced'] is False

    def test_query_limits(self):
        work_group = self._parse({
            'BytesScannedCutoffPerQuery': 10737418240,
            'RequesterPaysEnabled': True,
        })

        assert work_group['bytes_scanned_cutoff_per_query'] == 10737418240
        assert work_group['requester_pays_enabled'] is True

    def test_no_query_limit(self):
        # None means a single query may read as much as it can reach, which is not the same as zero
        work_group = self._parse({})

        assert work_group['bytes_scanned_cutoff_per_query'] is None
        assert work_group['requester_pays_enabled'] is False


class TestAWSAthenaWorkGroupResultConfiguration(unittest.TestCase):

    @staticmethod
    def _parse(configuration):
        work_group = {}
        WorkGroups._parse_result_configuration(configuration, work_group)
        return work_group

    def test_results_encrypted_with_a_customer_managed_key(self):
        work_group = self._parse({
            'ResultConfiguration': {
                'OutputLocation': 's3://analytics-query-results/prod/',
                'EncryptionConfiguration': {
                    'EncryptionOption': 'SSE_KMS',
                    'KmsKey': 'arn:aws:kms:eu-west-1:123456789012:key/abcd1234-56ef-78ab-90cd-ef1234567890',
                },
                'ExpectedBucketOwner': '123456789012',
                'AclConfiguration': {'S3AclOption': 'BUCKET_OWNER_FULL_CONTROL'},
            },
        })

        assert work_group['results_encrypted'] is True
        assert work_group['results_encryption_with_cmk'] is True
        assert work_group['results_bucket'] == 'analytics-query-results'
        assert work_group['results_bucket_owner_verified'] is True
        assert work_group['results_acl_option'] == 'BUCKET_OWNER_FULL_CONTROL'

    def test_client_side_encryption_also_names_a_key(self):
        work_group = self._parse({
            'ResultConfiguration': {
                'OutputLocation': 's3://analytics-query-results/prod/',
                'EncryptionConfiguration': {'EncryptionOption': 'CSE_KMS', 'KmsKey': 'alias/athena'},
            },
        })

        assert work_group['results_encryption_with_cmk'] is True

    def test_s3_managed_encryption_is_not_a_customer_managed_key(self):
        # SSE_S3 encrypts under a key S3 owns, so there is no policy to restrict and no grant to
        # revoke: the results are protected by the bucket permissions and by nothing else
        work_group = self._parse({
            'ResultConfiguration': {
                'OutputLocation': 's3://analytics-query-results/prod/',
                'EncryptionConfiguration': {'EncryptionOption': 'SSE_S3'},
            },
        })

        assert work_group['results_encrypted'] is True
        assert work_group['results_encryption_with_cmk'] is False
        assert work_group['results_encryption_kms_key'] is None

    def test_no_result_configuration_at_all(self):
        # A workgroup that fixes nothing leaves the location and the encryption to whatever each
        # query asks for
        work_group = self._parse({})

        assert work_group['results_output_location'] is None
        assert work_group['results_bucket'] is None
        assert work_group['results_encrypted'] is False
        assert work_group['results_bucket_owner_verified'] is False
        assert work_group['managed_query_results_enabled'] is False

    def test_athena_managed_storage(self):
        # Managed storage keeps the results in an account AWS owns, so there is no bucket of this
        # account to secure and no result location to report
        work_group = self._parse({
            'ManagedQueryResultsConfiguration': {
                'Enabled': True,
                'EncryptionConfiguration': {
                    'KmsKey': 'arn:aws:kms:eu-west-1:123456789012:key/abcd1234-56ef-78ab-90cd-ef1234567890',
                },
            },
        })

        assert work_group['managed_query_results_enabled'] is True
        assert work_group['managed_query_results_with_cmk'] is True
        assert work_group['results_encrypted'] is False
        assert work_group['results_output_location'] is None

    def test_output_location_that_is_not_an_s3_url(self):
        work_group = self._parse({'ResultConfiguration': {'OutputLocation': 'not-a-url'}})

        assert work_group['results_output_location'] == 'not-a-url'
        assert work_group['results_bucket'] is None

    def test_output_location_without_a_prefix(self):
        work_group = self._parse({'ResultConfiguration': {'OutputLocation': 's3://analytics-query-results'}})

        assert work_group['results_bucket'] == 'analytics-query-results'


class TestAWSAthenaWorkGroupEngineVersion(unittest.TestCase):

    @staticmethod
    def _parse(configuration):
        work_group = {}
        WorkGroups._parse_engine_version(configuration, work_group)
        return work_group

    def test_engine_version_left_on_auto(self):
        work_group = self._parse({
            'EngineVersion': {
                'SelectedEngineVersion': 'AUTO',
                'EffectiveEngineVersion': 'Athena engine version 3',
            },
        })

        assert work_group['engine_version_auto_upgrade'] is True
        assert work_group['effective_engine_version'] == 'Athena engine version 3'

    def test_engine_version_pinned(self):
        work_group = self._parse({
            'EngineVersion': {
                'SelectedEngineVersion': 'Athena engine version 2',
                'EffectiveEngineVersion': 'Athena engine version 2',
            },
        })

        assert work_group['engine_version_auto_upgrade'] is False
        assert work_group['selected_engine_version'] == 'Athena engine version 2'

    def test_engine_version_absent_from_the_configuration(self):
        # AUTO is what Athena applies when nothing is selected
        work_group = self._parse({})

        assert work_group['selected_engine_version'] is None
        assert work_group['engine_version_auto_upgrade'] is True


class TestAWSAthenaWorkGroupMonitoring(unittest.TestCase):

    @staticmethod
    def _parse(configuration):
        work_group = {}
        WorkGroups._parse_monitoring(configuration, work_group)
        return work_group

    def test_metrics_and_logs_enabled(self):
        work_group = self._parse({
            'PublishCloudWatchMetricsEnabled': True,
            'MonitoringConfiguration': {
                'CloudWatchLoggingConfiguration': {
                    'Enabled': True,
                    'LogGroup': '/aws/athena/analytics',
                },
                'S3LoggingConfiguration': {
                    'Enabled': True,
                    'LogLocation': 's3://analytics-spark-logs/',
                },
                'ManagedLoggingConfiguration': {'Enabled': True},
            },
        })

        assert work_group['publish_cloudwatch_metrics_enabled'] is True
        assert work_group['cloudwatch_log_group'] == '/aws/athena/analytics'
        assert work_group['s3_log_location'] == 's3://analytics-spark-logs/'
        assert work_group['managed_logging_enabled'] is True

    def test_no_monitoring_configuration(self):
        work_group = self._parse({})

        assert work_group['publish_cloudwatch_metrics_enabled'] is False
        assert work_group['cloudwatch_logging_enabled'] is False
        assert work_group['s3_logging_enabled'] is False
        assert work_group['managed_logging_enabled'] is False


class TestAWSAthenaWorkGroupSpark(unittest.TestCase):

    @staticmethod
    def _parse(configuration):
        work_group = {}
        WorkGroups._parse_spark(configuration, work_group)
        return work_group

    def test_spark_workgroup_with_a_customer_managed_key(self):
        work_group = self._parse({
            'ExecutionRole': 'arn:aws:iam::123456789012:role/AthenaSparkExecutionRole',
            'CustomerContentEncryptionConfiguration': {
                'KmsKey': 'arn:aws:kms:eu-west-1:123456789012:key/abcd1234-56ef-78ab-90cd-ef1234567890',
            },
        })

        assert work_group['spark_enabled'] is True
        assert work_group['customer_content_encryption_with_cmk'] is True

    def test_spark_workgroup_without_a_key(self):
        work_group = self._parse({
            'ExecutionRole': 'arn:aws:iam::123456789012:role/AthenaSparkExecutionRole',
        })

        assert work_group['spark_enabled'] is True
        assert work_group['customer_content_encryption_with_cmk'] is False

    def test_sql_workgroup_has_no_execution_role(self):
        # The customer content key only protects the notebooks and the calculation results of a Spark
        # workgroup, so a SQL workgroup missing one is not missing anything
        work_group = self._parse({})

        assert work_group['spark_enabled'] is False
        assert work_group['customer_content_encryption_with_cmk'] is False


class TestAWSAthenaWorkGroupIdentity(unittest.TestCase):

    @staticmethod
    def _parse(configuration):
        work_group = {}
        WorkGroups._parse_identity(configuration, work_group)
        return work_group

    def test_identity_center_and_access_grants_enabled(self):
        work_group = self._parse({
            'IdentityCenterConfiguration': {
                'EnableIdentityCenter': True,
                'IdentityCenterInstanceArn': 'arn:aws:sso:::instance/ssoins-1111aaaa2222bbbb',
            },
            'QueryResultsS3AccessGrantsConfiguration': {
                'EnableS3AccessGrants': True,
                'CreateUserLevelPrefix': True,
                'AuthenticationType': 'DIRECTORY_IDENTITY',
            },
        })

        assert work_group['identity_center_enabled'] is True
        assert work_group['s3_access_grants_enabled'] is True
        assert work_group['s3_access_grants_user_level_prefix'] is True

    def test_no_identity_configuration(self):
        work_group = self._parse({})

        assert work_group['identity_center_enabled'] is False
        assert work_group['s3_access_grants_enabled'] is False
        assert work_group['s3_access_grants_user_level_prefix'] is False


class TestAWSAthenaWorkGroupParsing(unittest.TestCase):

    @staticmethod
    def _parse(raw_work_group):
        work_groups = WorkGroups.__new__(WorkGroups)
        work_groups.region = 'eu-west-1'
        return work_groups._parse_work_group(raw_work_group)

    def test_work_group_is_keyed_by_a_hash_of_its_name(self):
        # A workgroup name may contain dots, which the recursion the rule engine walks the config
        # with would otherwise read as levels
        id, work_group = self._parse({
            'Name': 'analytics.prod',
            'State': 'ENABLED',
            'CreationTime': datetime(2023, 4, 11, 8, 12, 3),
            'arn': 'arn:aws:athena:eu-west-1:123456789012:workgroup/analytics.prod',
            'tags': {'env': 'prod'},
            'Configuration': {},
        })

        assert id == work_group['id']
        assert '.' not in id
        assert work_group['name'] == 'analytics.prod'
        assert work_group['region'] == 'eu-west-1'
        assert work_group['creation_time'] == '2023-04-11 08:12:03'
        assert work_group['tags'] == {'env': 'prod'}

    def test_work_group_without_a_configuration(self):
        # GetWorkGroup returns no Configuration for a workgroup created without one, and every
        # setting a rule reads still has to be present
        _, work_group = self._parse({'Name': 'primary', 'State': 'ENABLED'})

        assert work_group['enforce_workgroup_configuration'] is False
        assert work_group['results_encrypted'] is False
        assert work_group['publish_cloudwatch_metrics_enabled'] is False
        assert work_group['spark_enabled'] is False
        assert work_group['creation_time'] is None


class TestAWSAthenaDataCatalogParsing(unittest.TestCase):

    @staticmethod
    def _parse(raw_data_catalog):
        data_catalogs = DataCatalogs.__new__(DataCatalogs)
        data_catalogs.region = 'eu-west-1'
        return data_catalogs._parse_data_catalog(raw_data_catalog)

    def test_glue_data_catalog_is_not_external(self):
        id, data_catalog = self._parse({
            'Name': 'AwsDataCatalog',
            'Type': 'GLUE',
            'Parameters': {'catalog-id': '123456789012'},
        })

        assert id == data_catalog['id']
        assert data_catalog['external'] is False
        assert data_catalog['failed'] is False

    def test_lambda_catalog_is_external(self):
        _, data_catalog = self._parse({
            'Name': 'orders_hive',
            'Type': 'LAMBDA',
            'Status': 'CREATE_COMPLETE',
            'Parameters': {
                'metadata-function': 'arn:aws:lambda:eu-west-1:123456789012:function:hive-connector',
                'record-function': 'arn:aws:lambda:eu-west-1:123456789012:function:hive-connector',
            },
        })

        assert data_catalog['external'] is True
        assert data_catalog['failed'] is False
        assert 'metadata-function' in data_catalog['parameters']

    def test_catalog_left_behind_by_a_failed_clean_up(self):
        _, data_catalog = self._parse({
            'Name': 'orders_snowflake',
            'Type': 'FEDERATED',
            'ConnectionType': 'SNOWFLAKE',
            'Status': 'DELETE_FAILED',
            'Error': 'The connector stack could not be deleted',
        })

        assert data_catalog['failed'] is True
        assert data_catalog['connection_type'] == 'SNOWFLAKE'

    def test_catalog_whose_type_could_not_be_read(self):
        # A catalog kept from the listing alone rather than dropped, so an unknown type is not
        # reported as an external source
        _, data_catalog = self._parse({'Name': 'orders_hive'})

        assert data_catalog['external'] is False
        assert data_catalog['failed'] is False
        assert data_catalog['parameters'] == {}


if __name__ == '__main__':
    unittest.main()
