from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id

# The encryption options that name a KMS key. SSE_S3 is the remaining one and encrypts the results
# with the key S3 manages for the bucket, which no policy of the account governs.
KMS_ENCRYPTION_OPTIONS = ('SSE_KMS', 'CSE_KMS')


class WorkGroups(AWSResources):
    """The Athena workgroups of a region.

    A workgroup is the only place where Athena decides anything: it fixes where the results of every
    query run under it are written, whether they are encrypted and with whose key, whether the client
    running the query may override any of that, and whether the query is metered in CloudWatch. Query
    results are a full copy of whatever the query returned, so the result location is a second, and
    usually unnoticed, copy of every table an analyst has ever read."""

    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw_work_group in await self.facade.athena.get_work_groups(self.region):
            id, work_group = self._parse_work_group(raw_work_group)
            self[id] = work_group

    def _parse_work_group(self, raw_work_group):
        created = raw_work_group.get('CreationTime')
        name = raw_work_group.get('Name')

        work_group = {}
        # A workgroup name may contain dots, which the recursion the rule engine walks the config with
        # would read as levels, so the name is hashed into the id and kept beside it
        work_group['id'] = get_non_provider_id(name) if name else None
        work_group['name'] = name
        work_group['arn'] = raw_work_group.get('arn')
        work_group['region'] = self.region
        work_group['description'] = raw_work_group.get('Description')
        # ENABLED or DISABLED. A disabled workgroup runs no query until it is enabled again, which
        # takes no change to any of the settings below
        work_group['state'] = raw_work_group.get('State')
        work_group['creation_time'] = created.strftime('%Y-%m-%d %H:%M:%S') if created else None
        work_group['tags'] = raw_work_group.get('tags') or {}

        configuration = raw_work_group.get('Configuration') or {}
        self._parse_enforcement(configuration, work_group)
        self._parse_result_configuration(configuration, work_group)
        self._parse_engine_version(configuration, work_group)
        self._parse_monitoring(configuration, work_group)
        self._parse_spark(configuration, work_group)
        self._parse_identity(configuration, work_group)

        return work_group['id'], work_group

    @staticmethod
    def _parse_enforcement(configuration, work_group):
        """Whether the settings of the workgroup are settings or suggestions.

        With EnforceWorkGroupConfiguration off - which is what Athena applies when the workgroup is
        created through the API without saying otherwise - a client may pass its own OutputLocation
        and its own EncryptionConfiguration with every query, and Athena uses those instead. The
        result location and the encryption reported for the workgroup then describe what an obedient
        client would do, not what any query actually did.

        EnableMinimumEncryptionConfiguration is the narrower guarantee for that case: the workgroup
        keeps letting clients choose, but Athena refuses any choice weaker than the one configured."""

        work_group['enforce_workgroup_configuration'] = bool(
            configuration.get('EnforceWorkGroupConfiguration'))
        work_group['minimum_encryption_enforced'] = bool(
            configuration.get('EnableMinimumEncryptionConfiguration'))
        # Lets a query under this workgroup read a requester-pays bucket, which is how data owned by
        # another account is read while this one is billed for the transfer
        work_group['requester_pays_enabled'] = bool(configuration.get('RequesterPaysEnabled'))
        # The per-query data scanned limit, the only guardrail against a single query reading a whole
        # data lake. None means unlimited.
        work_group['bytes_scanned_cutoff_per_query'] = configuration.get('BytesScannedCutoffPerQuery')

    @staticmethod
    def _parse_result_configuration(configuration, work_group):
        """Where the results of every query go, and what protects them there.

        Athena writes the full result set of each query, plus its metadata and the manifest of the
        files it read, to the result location, and keeps it there until something deletes it. Whoever
        can read that prefix can read the output of every query without any permission on the tables
        that were queried."""

        result_configuration = configuration.get('ResultConfiguration') or {}
        encryption = result_configuration.get('EncryptionConfiguration') or {}
        acl = result_configuration.get('AclConfiguration') or {}
        managed = configuration.get('ManagedQueryResultsConfiguration') or {}
        managed_encryption = managed.get('EncryptionConfiguration') or {}

        output_location = result_configuration.get('OutputLocation')
        encryption_option = encryption.get('EncryptionOption')

        work_group['results_output_location'] = output_location
        work_group['results_bucket'] = _bucket_of(output_location)
        work_group['results_encryption_option'] = encryption_option
        work_group['results_encryption_kms_key'] = encryption.get('KmsKey')
        work_group['results_encrypted'] = bool(encryption_option)
        # SSE_S3 leaves the results under a key S3 owns: there is no key policy to deny, no grant to
        # revoke and no CloudTrail record of a decryption
        work_group['results_encryption_with_cmk'] = encryption_option in KMS_ENCRYPTION_OPTIONS
        # Set to the account expected to own the result bucket, which makes Athena refuse to write
        # anywhere else. Without it a client that may override the location can have the results
        # delivered to a bucket in an account it chooses.
        work_group['results_expected_bucket_owner'] = result_configuration.get('ExpectedBucketOwner')
        work_group['results_bucket_owner_verified'] = bool(result_configuration.get('ExpectedBucketOwner'))
        # BUCKET_OWNER_FULL_CONTROL, needed for a result bucket owned by another account to stay
        # readable by its owner
        work_group['results_acl_option'] = acl.get('S3AclOption')

        # Athena-managed storage keeps the results in an account AWS owns instead of a bucket of this
        # one, so a workgroup using it has no result location to secure and is always encrypted
        work_group['managed_query_results_enabled'] = bool(managed.get('Enabled'))
        work_group['managed_query_results_kms_key'] = managed_encryption.get('KmsKey')
        work_group['managed_query_results_with_cmk'] = bool(managed_encryption.get('KmsKey'))

    @staticmethod
    def _parse_engine_version(configuration, work_group):
        """AUTO lets Athena move the workgroup onto the engine version it currently supports.

        A pinned version stays where it was put, including on an engine AWS has stopped maintaining,
        so the correctness and security fixes that land in later versions never reach the queries of
        the workgroup."""

        engine_version = configuration.get('EngineVersion') or {}
        selected = engine_version.get('SelectedEngineVersion')

        work_group['selected_engine_version'] = selected
        # What the queries actually ran on, which lags the selection until the next upgrade window
        work_group['effective_engine_version'] = engine_version.get('EffectiveEngineVersion')
        # AUTO is what Athena applies when nothing is selected
        work_group['engine_version_auto_upgrade'] = selected in (None, 'AUTO')

    @staticmethod
    def _parse_monitoring(configuration, work_group):
        """CloudWatch query metrics, and the log destinations of the Spark calculations.

        Without the query metrics there is no record of how much data the workgroup scanned, by how
        many queries, or when that changed, so a single query reading every table of a data lake
        looks exactly like a normal day."""

        work_group['publish_cloudwatch_metrics_enabled'] = bool(
            configuration.get('PublishCloudWatchMetricsEnabled'))

        monitoring = configuration.get('MonitoringConfiguration') or {}
        cloudwatch_logging = monitoring.get('CloudWatchLoggingConfiguration') or {}
        managed_logging = monitoring.get('ManagedLoggingConfiguration') or {}
        s3_logging = monitoring.get('S3LoggingConfiguration') or {}

        work_group['cloudwatch_logging_enabled'] = bool(cloudwatch_logging.get('Enabled'))
        work_group['cloudwatch_log_group'] = cloudwatch_logging.get('LogGroup')
        work_group['s3_logging_enabled'] = bool(s3_logging.get('Enabled'))
        work_group['s3_log_location'] = s3_logging.get('LogLocation')
        work_group['managed_logging_enabled'] = bool(managed_logging.get('Enabled'))

    @staticmethod
    def _parse_spark(configuration, work_group):
        """The Spark side of a workgroup, which exists only when one was created for notebooks.

        A Spark workgroup runs code rather than SQL, under an execution role of its own, and the
        notebooks, their cells and the results of every calculation are stored by Athena. The
        customer content key is what protects that store; without one it is encrypted under a key
        AWS owns."""

        execution_role = configuration.get('ExecutionRole')
        content_encryption = configuration.get('CustomerContentEncryptionConfiguration') or {}

        work_group['execution_role'] = execution_role
        work_group['spark_enabled'] = bool(execution_role)
        work_group['customer_content_encryption_kms_key'] = content_encryption.get('KmsKey')
        work_group['customer_content_encryption_with_cmk'] = bool(content_encryption.get('KmsKey'))
        # Spark properties and the extra engine settings, kept as given since they are what a
        # notebook session is configured with
        work_group['additional_configuration'] = configuration.get('AdditionalConfiguration')

    @staticmethod
    def _parse_identity(configuration, work_group):
        """Whether the workgroup is reached through IAM Identity Center rather than by assuming a
        role, and whether the results are read back through S3 Access Grants.

        Identity Center is what makes a query attributable to a person rather than to a shared role,
        and the user-level prefix is what keeps one analyst's results out of another's reach."""

        identity_center = configuration.get('IdentityCenterConfiguration') or {}
        access_grants = configuration.get('QueryResultsS3AccessGrantsConfiguration') or {}

        work_group['identity_center_enabled'] = bool(identity_center.get('EnableIdentityCenter'))
        work_group['identity_center_instance_arn'] = identity_center.get('IdentityCenterInstanceArn')
        work_group['s3_access_grants_enabled'] = bool(access_grants.get('EnableS3AccessGrants'))
        # Gives each authenticated identity its own prefix under the result location, so an access
        # grant can be scoped to one user instead of to the whole workgroup output
        work_group['s3_access_grants_user_level_prefix'] = bool(access_grants.get('CreateUserLevelPrefix'))
        work_group['s3_access_grants_authentication_type'] = access_grants.get('AuthenticationType')


def _bucket_of(output_location):
    """The bucket name out of an s3://bucket/prefix result location, so the report names the bucket a
    reader has to go and check the policy of."""

    if not output_location or not output_location.startswith('s3://'):
        return None

    return output_location[len('s3://'):].split('/')[0] or None
