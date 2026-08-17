from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.utils import policy_restricts_to_vpc_endpoint


class Tables(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super(Tables, self).__init__(facade)
        self.region = region

    async def fetch_all(self):
        raw_tables = await self.facade.dynamodb.get_tables(self.region)
        for raw_table in raw_tables:
            name, resource = self._parse_table(raw_table)
            self[name] = resource

    def _parse_table(self, raw_table):
        table_dict = {}
        table_dict['name'] = raw_table.get('TableName')
        table_dict['id'] = raw_table.get('TableId')
        table_dict['arn'] = raw_table.get('TableArn')
        table_dict['attribute_definitions'] = raw_table.get('AttributeDefinitions')
        table_dict['key_schema'] = raw_table.get('KeySchema')
        table_dict['table_status'] = raw_table.get('TableStatus')
        table_dict['creation_date_time'] = raw_table.get('CreationDateTime')
        table_dict['provisioned_throughput'] = raw_table.get('ProvisionedThroughput')
        table_dict['table_size_bytes'] = raw_table.get('TableSizeBytes')
        table_dict['item_count'] = raw_table.get('ItemCount')
        table_dict['backup_summaries'] = raw_table.get('BackupSummaries')
        table_dict['continuous_backups'] = raw_table.get('ContinuousBackups')
        table_dict['deletion_protection_enabled'] = raw_table.get('DeletionProtectionEnabled')
        table_dict['tags'] = raw_table.get('tags')

        table_dict['automatic_backups_enabled'] = \
            raw_table['ContinuousBackups']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus'] == 'ENABLED' \
                if 'ContinuousBackups' in raw_table else None

        if "SSEDescription" in raw_table:
            table_dict["sse_enabled"] = True
        else:
            table_dict["sse_enabled"] = False

        # SSEDescription is only returned when the table is encrypted with an AWS managed or a customer
        # managed key; a table left on the AWS owned key reports nothing at all
        sse_description = raw_table.get('SSEDescription', {})
        table_dict['sse_status'] = sse_description.get('Status')
        table_dict['sse_type'] = sse_description.get('SSEType')
        table_dict['kms_master_key_arn'] = sse_description.get('KMSMasterKeyArn')

        self._parse_stream(raw_table, table_dict)
        self._parse_replicas(raw_table, table_dict)
        self._parse_policies(raw_table, table_dict)

        return table_dict['id'], table_dict

    @staticmethod
    def _parse_stream(raw_table, table_dict):
        stream_specification = raw_table.get('StreamSpecification', {})
        table_dict['stream_enabled'] = stream_specification.get('StreamEnabled', False)
        table_dict['stream_view_type'] = stream_specification.get('StreamViewType')
        table_dict['latest_stream_arn'] = raw_table.get('LatestStreamArn')
        table_dict['latest_stream_label'] = raw_table.get('LatestStreamLabel')

        # Records handed over to a Kinesis data stream leave the table's own encryption behind and are
        # protected by whatever the destination stream is configured with
        table_dict['kinesis_data_stream_destinations'] = raw_table.get('KinesisDataStreamDestinations')

    @staticmethod
    def _parse_replicas(raw_table, table_dict):
        table_dict['global_table_version'] = raw_table.get('GlobalTableVersion')

        replicas = {}
        for raw_replica in raw_table.get('Replicas', []):
            region = raw_replica.get('RegionName')
            # KMSMasterKeyId is only reported for a replica encrypted with a customer managed key,
            # its absence means the replica falls back to the AWS owned key in its own region
            key_id = raw_replica.get('KMSMasterKeyId')
            replicas[region] = {
                'id': region,
                'name': region,
                'region': region,
                'replica_status': raw_replica.get('ReplicaStatus'),
                'replica_status_description': raw_replica.get('ReplicaStatusDescription'),
                'kms_master_key_id': key_id,
                'sse_enabled': key_id is not None,
                'table_class': raw_replica.get('ReplicaTableClassSummary', {}).get('TableClass'),
                'global_secondary_indexes': raw_replica.get('GlobalSecondaryIndexes')
            }
        table_dict['replicas'] = replicas
        table_dict['replicas_count'] = len(replicas)

    @staticmethod
    def _parse_policies(raw_table, table_dict):
        # Only set the attributes when a policy exists, so that rules can tell a table with no
        # resource-based policy apart from one whose policy has no statement
        resource_policy = raw_table.get('ResourcePolicy')
        if resource_policy:
            table_dict['policy'] = resource_policy
        stream_policy = raw_table.get('StreamResourcePolicy')
        if stream_policy:
            table_dict['stream_policy'] = stream_policy

        table_dict['policy_restricts_to_vpc_endpoint'] = \
            policy_restricts_to_vpc_endpoint(resource_policy) if resource_policy else False
