import json

from botocore.exceptions import ConnectionError as BotoConnectionError

from ScoutSuite.core.console import print_exception, print_warning
from ScoutSuite.providers.aws.facade.base import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently, get_and_set_concurrently, map_concurrently


class DynamoDBFacade(AWSBaseFacade):
    _GET_TABLES_BATCH_SIZE = 100

    async def get_tables(self, region):
        try:
            tables_names = await AWSFacadeUtils.get_all_pages('dynamodb', region, self.session, 'list_tables',
                                                              'TableNames')
            tables = await map_concurrently(self._get_table, tables_names, region=region)
            # Tables that could not be described are returned as None
            return [table for table in tables if table]
        except Exception as e:
            print_exception('Failed to get DynamoDB tables: {}'.format(e))
            return []

    async def _get_table(self, table_name: str, region: str):
        client = AWSFacadeUtils.get_client('dynamodb', self.session, region)

        try:
            table = await run_concurrently(lambda: client.describe_table(TableName=table_name)['Table'])
        except Exception as e:
            if 'ResourceNotFoundException' in str(e):
                print_warning('Failed to get DynamoDB table: {}'.format(e))
            else:
                print_exception('Failed to get DynamoDB table: {}'.format(e))
            return None
        else:
            await get_and_set_concurrently(
                [self._get_and_set_backup,
                 self._get_and_set_continuous_backups,
                 self._get_and_set_resource_policy,
                 self._get_and_set_stream_resource_policy,
                 self._get_and_set_kinesis_destinations,
                 self._get_and_set_tags],
                [table],
                region=region)

        return table

    async def _get_and_set_backup(self, table: {}, region: str):
        client = AWSFacadeUtils.get_client('dynamodb', self.session, region)

        try:
            summaries = await run_concurrently(lambda: client.list_backups(TableName=table['TableName']))
            table['BackupSummaries'] = summaries.get('BackupSummaries')
        except Exception as e:
            if 'ResourceNotFoundException' in str(e):
                print_warning('Failed to list DynamoDB table backups: {}'.format(e))
            else:
                print_exception('Failed to list DynamoDB table backups: {}'.format(e))

    async def _get_and_set_continuous_backups(self, table: {}, region: str):
        client = AWSFacadeUtils.get_client('dynamodb', self.session, region)

        try:
            description = await run_concurrently(
                lambda: client.describe_continuous_backups(TableName=table['TableName']))
            table['ContinuousBackups'] = description.get('ContinuousBackupsDescription')
        except Exception as e:
            if 'ResourceNotFoundException' in str(e):
                print_warning('Failed to describe DynamoDB table continuous backups: {}'.format(e))
            else:
                print_exception('Failed to describe DynamoDB table continuous backups: {}'.format(e))

    async def _get_and_set_resource_policy(self, table: {}, region: str):
        table['ResourcePolicy'] = await self._get_resource_policy(table['TableArn'], region)

    async def _get_and_set_stream_resource_policy(self, table: {}, region: str):
        # A stream only has a resource-based policy of its own once one has been attached to it, and only
        # tables with a stream enabled expose a stream ARN to query.
        if table.get('LatestStreamArn'):
            table['StreamResourcePolicy'] = await self._get_resource_policy(table['LatestStreamArn'], region)

    async def _get_resource_policy(self, resource_arn: str, region: str):
        """Return the resource-based policy attached to a table or a stream, None when there is none."""

        client = AWSFacadeUtils.get_client('dynamodb', self.session, region)

        # Resource-based policies were introduced in March 2024, keep working with older botocore versions
        if not hasattr(client, 'get_resource_policy'):
            print_warning('Failed to get DynamoDB resource policy for {}: the installed botocore version does not '
                          'support GetResourcePolicy'.format(resource_arn))
            return None

        try:
            policy = await run_concurrently(
                lambda: client.get_resource_policy(ResourceArn=resource_arn)['Policy'])
        except Exception as e:
            # Having no resource-based policy at all is the common case, not an error
            if 'PolicyNotFoundException' in str(e):
                return None
            elif 'ResourceNotFoundException' in str(e):
                print_warning('Failed to get DynamoDB resource policy: {}'.format(e))
            else:
                print_exception('Failed to get DynamoDB resource policy: {}'.format(e))
            return None

        try:
            return json.loads(policy)
        except ValueError as e:
            print_exception('Failed to parse DynamoDB resource policy for {}: {}'.format(resource_arn, e))
            return None

    async def _get_and_set_kinesis_destinations(self, table: {}, region: str):
        client = AWSFacadeUtils.get_client('dynamodb', self.session, region)

        try:
            destinations = await run_concurrently(
                lambda: client.describe_kinesis_streaming_destination(TableName=table['TableName']))
            table['KinesisDataStreamDestinations'] = destinations.get('KinesisDataStreamDestinations')
        except Exception as e:
            if 'ResourceNotFoundException' in str(e):
                print_warning('Failed to describe DynamoDB Kinesis streaming destination: {}'.format(e))
            else:
                print_exception('Failed to describe DynamoDB Kinesis streaming destination: {}'.format(e))

    async def _get_and_set_tags(self, table: {}, region: str):
        client = AWSFacadeUtils.get_client('dynamodb', self.session, region)

        try:
            tags = await run_concurrently(
                lambda: client.list_tags_of_resource(ResourceArn=table['TableArn']))
            table['tags'] = tags.get('Tags')
        except Exception as e:
            if 'ResourceNotFoundException' in str(e):
                print_warning('Failed to describe DynamoDB table tags: {}'.format(e))
            else:
                print_exception('Failed to describe DynamoDB table tags: {}'.format(e))

    async def get_dax_clusters(self, region: str):
        client = AWSFacadeUtils.get_client('dax', self.session, region)
        if client is None:
            return []

        # DescribeClusters is not exposed as a paginator by every botocore version, page through it by hand
        clusters = []
        next_token = None
        try:
            while True:
                arguments = {'NextToken': next_token} if next_token else {}
                response = await run_concurrently(lambda: client.describe_clusters(**arguments))
                clusters.extend(response.get('Clusters', []))
                next_token = response.get('NextToken')
                if not next_token:
                    break
        except BotoConnectionError as e:
            # DAX is not available in every region in which DynamoDB is, and its endpoint simply
            # does not resolve in those
            print_warning('Failed to describe DAX clusters: {}'.format(e))
            return []
        except Exception as e:
            print_exception('Failed to describe DAX clusters: {}'.format(e))
            return []

        await get_and_set_concurrently([self._get_and_set_dax_cluster_tags], clusters, region=region)
        return clusters

    async def _get_and_set_dax_cluster_tags(self, cluster: {}, region: str):
        client = AWSFacadeUtils.get_client('dax', self.session, region)

        try:
            tags = await run_concurrently(lambda: client.list_tags(ResourceName=cluster['ClusterArn']))
            cluster['tags'] = tags.get('Tags')
        except Exception as e:
            if 'ClusterNotFoundFault' in str(e):
                print_warning('Failed to list DAX cluster tags: {}'.format(e))
            else:
                print_exception('Failed to list DAX cluster tags: {}'.format(e))
