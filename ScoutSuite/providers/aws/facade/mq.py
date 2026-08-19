import base64

from asyncio import Lock
from typing import Dict, List, Optional

from ScoutSuite.core.console import print_exception
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently, get_and_set_concurrently, map_concurrently


class MQFacade(AWSBaseFacade):
    _engine_versions_cache_locks = {}
    _engine_versions_cache = {}
    _configuration_revisions_cache_locks = {}
    _configuration_revisions_cache = {}

    async def get_brokers(self, region: str) -> List[Dict]:
        try:
            broker_summaries = await AWSFacadeUtils.get_all_pages(
                'mq', region, self.session, 'list_brokers', 'BrokerSummaries')
        except Exception as e:
            print_exception(f'Failed to list Amazon MQ brokers: {e}')
            return []

        # ListBrokers only reports the name, the engine and the state. Everything that decides who
        # can reach a broker, and what is recorded when they do, comes from DescribeBroker.
        brokers = [broker for broker in
                   await map_concurrently(self._get_broker, broker_summaries, region=region)
                   if broker]

        await get_and_set_concurrently(
            [self._get_and_set_users, self._get_and_set_configuration], brokers, region=region)

        return brokers

    async def get_configurations(self, region: str) -> List[Dict]:
        return await self._list_all(region, 'list_configurations', 'Configurations')

    async def get_supported_engine_versions(self, region: str, engine_type: str) -> List[str]:
        """The engine versions Amazon MQ still offers for a given engine. Asking the API avoids
        transcribing a support calendar AWS moves on its own schedule, and the answer is the same for
        every broker of the region, so it is only fetched once."""

        # The lock is only created here, as an asyncio lock binds to the running loop
        async with self._engine_versions_cache_locks.setdefault((region, engine_type), Lock()):
            if (region, engine_type) not in self._engine_versions_cache:
                engine_types = await self._list_all(
                    region, 'describe_broker_engine_types', 'BrokerEngineTypes', EngineType=engine_type)

                self._engine_versions_cache[(region, engine_type)] = [
                    version['Name'] for engine in engine_types
                    for version in engine.get('EngineVersions') or [] if version.get('Name')
                ]

        return self._engine_versions_cache[(region, engine_type)]

    async def _get_broker(self, broker_summary: Dict, region: str) -> Optional[Dict]:
        client = AWSFacadeUtils.get_client('mq', self.session, region)
        try:
            broker = await run_concurrently(
                lambda: client.describe_broker(BrokerId=broker_summary['BrokerId']))
        except Exception as e:
            print_exception(f'Failed to describe Amazon MQ broker {broker_summary.get("BrokerId")}: {e}')
            return None

        broker.pop('ResponseMetadata', None)
        return broker

    async def _get_and_set_users(self, broker: Dict, region: str):
        """Attach what each broker user may do. DescribeBroker only names them, while the web console
        access and the group membership that decide their reach take one call per user.

        Only ActiveMQ brokers have users the API describes: a RabbitMQ broker reports the name of the
        administrator it was created with and keeps its other users, and their permissions, inside
        RabbitMQ, so asking about them is an error rather than an empty answer."""

        users = broker.get('Users') or []
        if not users or broker.get('EngineType') != 'ACTIVEMQ':
            return

        broker['user_details'] = [
            user for user in await map_concurrently(
                self._get_user, users, region=region, broker_id=broker['BrokerId'])
            if user
        ]

    async def _get_user(self, user: Dict, region: str, broker_id: str) -> Optional[Dict]:
        client = AWSFacadeUtils.get_client('mq', self.session, region)
        try:
            user_details = await run_concurrently(
                lambda: client.describe_user(BrokerId=broker_id, Username=user['Username']))
        except Exception as e:
            print_exception(f'Failed to describe Amazon MQ user {user.get("Username")} '
                            f'of broker {broker_id}: {e}')
            return None

        user_details.pop('ResponseMetadata', None)
        return user_details

    async def _get_and_set_configuration(self, broker: Dict, region: str):
        """Attach the configuration revision the broker currently runs. On ActiveMQ the authorization
        map, the only thing standing between an authenticated client and every destination of the
        broker, is declared there and nowhere else."""

        current = (broker.get('Configurations') or {}).get('Current') or {}
        configuration_id, revision = current.get('Id'), current.get('Revision')
        if not configuration_id or revision is None:
            return

        data = await self._get_configuration_revision_data(region, configuration_id, revision)
        if data is not None:
            broker['configuration_data'] = data

    async def _get_configuration_revision_data(self, region: str, configuration_id: str,
                                               revision: int) -> Optional[str]:
        """Read one configuration revision. Revisions are immutable and a single one can be applied
        to several brokers, so each is only fetched once."""

        async with self._configuration_revisions_cache_locks.setdefault((configuration_id, revision), Lock()):
            if (configuration_id, revision) not in self._configuration_revisions_cache:
                client = AWSFacadeUtils.get_client('mq', self.session, region)
                try:
                    response = await run_concurrently(lambda: client.describe_configuration_revision(
                        ConfigurationId=configuration_id, ConfigurationRevision=str(revision)))
                    data = self._decode_configuration_data(response.get('Data'))
                except Exception as e:
                    print_exception(f'Failed to describe revision {revision} of Amazon MQ '
                                    f'configuration {configuration_id}: {e}')
                    data = None

                self._configuration_revisions_cache[(configuration_id, revision)] = data

        return self._configuration_revisions_cache[(configuration_id, revision)]

    async def _list_all(self, region: str, method_name: str, entity: str, **args) -> List[Dict]:
        """Page through a listing botocore does not describe as pageable. Only ListBrokers has a
        paginator on the mq client, so the configurations and the engine types are paged by hand."""

        client = AWSFacadeUtils.get_client('mq', self.session, region)

        entities, next_token = [], None
        while True:
            page_args = dict(args, NextToken=next_token) if next_token else dict(args)
            try:
                method = getattr(client, method_name)
                page = await run_concurrently(lambda arguments=page_args: method(**arguments))
            except Exception as e:
                print_exception(f'Failed to call {method_name} on the Amazon MQ API: {e}')
                return entities

            entities.extend(page.get(entity) or [])
            next_token = page.get('NextToken')
            if not next_token:
                return entities

    @staticmethod
    def _decode_configuration_data(data) -> Optional[str]:
        """The API hands a configuration revision over as base64. An ActiveMQ revision decodes to the
        broker XML, a RabbitMQ one to a cuttlefish properties file."""

        if not data:
            return None

        try:
            return base64.b64decode(data).decode('utf-8', errors='replace')
        except Exception as e:
            print_exception(f'Failed to decode an Amazon MQ configuration revision: {e}')
            return None
