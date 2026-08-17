import json

from asyncio import Lock
from typing import Dict, List, Optional

from botocore.exceptions import ClientError

from ScoutSuite.core.console import print_exception
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently, get_and_set_concurrently


class MSKFacade(AWSBaseFacade):
    # MSK is reached through the 'kafka' boto3 client, the service is only named msk in the console
    _kafka_versions_cache_locks = {}
    _kafka_versions_cache = {}
    _configuration_revisions_cache_locks = {}
    _configuration_revisions_cache = {}
    _key_managers_cache_locks = {}
    _key_managers_cache = {}

    async def get_clusters(self, region: str) -> List[Dict]:
        try:
            clusters = await AWSFacadeUtils.get_all_pages(
                'kafka', region, self.session, 'list_clusters_v2', 'ClusterInfoList')
        except Exception as e:
            print_exception(f'Failed to list MSK clusters: {e}')
            return []

        await get_and_set_concurrently(
            [self._get_and_set_cluster_policy,
             self._get_and_set_scram_secrets,
             self._get_and_set_configuration_revision],
            clusters, region=region)

        return clusters

    async def get_configurations(self, region: str) -> List[Dict]:
        try:
            configurations = await AWSFacadeUtils.get_all_pages(
                'kafka', region, self.session, 'list_configurations', 'Configurations')
        except Exception as e:
            print_exception(f'Failed to list MSK configurations: {e}')
            return []

        await get_and_set_concurrently(
            [self._get_and_set_latest_revision], configurations, region=region)

        return configurations

    async def get_kafka_version_statuses(self, region: str) -> Dict[str, str]:
        """Map every Apache Kafka version MSK knows about to ACTIVE or DEPRECATED. Asking the API
        avoids transcribing a support calendar that AWS changes on its own schedule."""

        # The lock is only created here, as an asyncio lock binds to the running loop
        async with self._kafka_versions_cache_locks.setdefault(region, Lock()):
            if region not in self._kafka_versions_cache:
                try:
                    versions = await AWSFacadeUtils.get_all_pages(
                        'kafka', region, self.session, 'list_kafka_versions', 'KafkaVersions')
                except Exception as e:
                    print_exception(f'Failed to list Kafka versions: {e}')
                    versions = []

                self._kafka_versions_cache[region] = {
                    version['Version']: version.get('Status')
                    for version in versions if version.get('Version')
                }

        return self._kafka_versions_cache[region]

    async def get_key_manager(self, region: str, key_id: str) -> Optional[str]:
        """Ask KMS who manages a key: AWS or CUSTOMER. MSK reports an at-rest key on every cluster,
        including the AWS managed alias/aws/kafka one it silently creates when none is given, so the
        key ARN alone does not say whether the account ever chose it. Returns None when the key
        cannot be read, so the distinction is reported as unknown rather than guessed."""

        async with self._key_managers_cache_locks.setdefault(key_id, Lock()):
            if key_id not in self._key_managers_cache:
                client = AWSFacadeUtils.get_client('kms', self.session, region)
                try:
                    response = await run_concurrently(lambda: client.describe_key(KeyId=key_id))
                    key_manager = response['KeyMetadata'].get('KeyManager')
                except Exception as e:
                    print_exception(f'Failed to describe KMS key {key_id}: {e}')
                    key_manager = None

                self._key_managers_cache[key_id] = key_manager

        return self._key_managers_cache[key_id]

    async def _get_and_set_cluster_policy(self, cluster: Dict, region: str):
        client = AWSFacadeUtils.get_client('kafka', self.session, region)
        try:
            response = await run_concurrently(
                lambda: client.get_cluster_policy(ClusterArn=cluster['ClusterArn']))
        except ClientError as e:
            # A cluster without a policy is the common case and answers with NotFoundException
            if e.response['Error']['Code'] != 'NotFoundException':
                print_exception(f'Failed to get MSK cluster policy: {e}')
            return
        except Exception as e:
            print_exception(f'Failed to get MSK cluster policy: {e}')
            return

        if response.get('Policy'):
            try:
                cluster['policy'] = json.loads(response['Policy'])
            except ValueError as e:
                print_exception(f'Failed to parse MSK cluster policy: {e}')

    async def _get_and_set_scram_secrets(self, cluster: Dict, region: str):
        # Serverless clusters only support IAM, asking them for SCRAM secrets is an error
        if cluster.get('ClusterType') == 'SERVERLESS':
            return

        try:
            cluster['scram_secrets'] = await AWSFacadeUtils.get_all_pages(
                'kafka', region, self.session, 'list_scram_secrets', 'SecretArnList',
                ClusterArn=cluster['ClusterArn'])
        except Exception as e:
            print_exception(f'Failed to list MSK SCRAM secrets: {e}')

    async def _get_and_set_configuration_revision(self, cluster: Dict, region: str):
        """Attach the server.properties of the configuration revision the cluster currently runs.
        Broker settings that decide who may read a topic live there and nowhere else."""

        software_info = (cluster.get('Provisioned') or {}).get('CurrentBrokerSoftwareInfo') or {}
        arn, revision = software_info.get('ConfigurationArn'), software_info.get('ConfigurationRevision')
        if not arn or revision is None:
            return

        properties = await self._get_configuration_properties(region, arn, revision)
        if properties is not None:
            cluster['server_properties'] = properties

    async def _get_and_set_latest_revision(self, configuration: Dict, region: str):
        revision = (configuration.get('LatestRevision') or {}).get('Revision')
        if not configuration.get('Arn') or revision is None:
            return

        properties = await self._get_configuration_properties(region, configuration['Arn'], revision)
        if properties is not None:
            configuration['server_properties'] = properties

    async def _get_configuration_properties(self, region: str, arn: str, revision: int) -> Optional[Dict]:
        """Read one configuration revision and parse its server.properties. Revisions are immutable
        and shared by every cluster using them, so each one is only fetched once."""

        async with self._configuration_revisions_cache_locks.setdefault((arn, revision), Lock()):
            if (arn, revision) not in self._configuration_revisions_cache:
                client = AWSFacadeUtils.get_client('kafka', self.session, region)
                try:
                    response = await run_concurrently(
                        lambda: client.describe_configuration_revision(Arn=arn, Revision=revision))
                    properties = self._parse_server_properties(response.get('ServerProperties'))
                except Exception as e:
                    print_exception(f'Failed to describe MSK configuration revision {revision} of {arn}: {e}')
                    properties = None

                self._configuration_revisions_cache[(arn, revision)] = properties

        return self._configuration_revisions_cache[(arn, revision)]

    @staticmethod
    def _parse_server_properties(server_properties) -> Dict[str, str]:
        """Turn the contents of a server.properties file into a dictionary. The API hands it over as
        raw bytes, in the java properties format: key=value lines, # or ! for comments."""

        if not server_properties:
            return {}

        if isinstance(server_properties, bytes):
            server_properties = server_properties.decode('utf-8', errors='replace')

        properties = {}
        for line in server_properties.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('!') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            properties[key.strip()] = value.strip()

        return properties
