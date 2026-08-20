from typing import Dict, List, Optional

import boto3

from ScoutSuite.core.console import print_exception
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.utils import format_arn
from ScoutSuite.providers.utils import run_concurrently, get_and_set_concurrently, map_concurrently


class AthenaFacade(AWSBaseFacade):
    def __init__(self, session: boto3.session.Session = None, partition: str = None, owner_id: str = None):
        super().__init__(session)
        # No Athena call returns the ARN of a workgroup or of a data catalog, and ListTagsForResource
        # takes nothing else, so the ARN has to be built from the partition and the account
        self.partition = partition
        self.owner_id = owner_id

    async def get_work_groups(self, region: str) -> List[Dict]:
        """The Athena workgroups of a region.

        ListWorkGroups reports the name, the state and the engine version only, while everything that
        decides where query results are written, whether they are encrypted, and whether a client may
        override either of those comes from GetWorkGroup."""

        summaries = await self._list_all(region, 'list_work_groups', 'WorkGroups')

        work_groups = [work_group for work_group in
                       await map_concurrently(self._get_work_group, summaries, region=region)
                       if work_group]

        await get_and_set_concurrently([self._get_and_set_tags], work_groups, region=region)

        return work_groups

    async def get_data_catalogs(self, region: str) -> List[Dict]:
        """The data catalogs a workgroup of the region may query.

        The summary already carries the type and the status, but not the parameters, which name the
        Lambda connector or the Glue catalog the queries actually read through, so each catalog is
        described."""

        summaries = await self._get_all_pages(region, 'list_data_catalogs', 'DataCatalogsSummary')

        data_catalogs = [data_catalog for data_catalog in
                         await map_concurrently(self._get_data_catalog, summaries, region=region)
                         if data_catalog]

        await get_and_set_concurrently([self._get_and_set_tags], data_catalogs, region=region)

        return data_catalogs

    async def _get_work_group(self, summary: Dict, region: str) -> Optional[Dict]:
        name = summary.get('Name')
        if not name:
            return None

        response = await self._call(region, 'get_work_group', WorkGroup=name)
        if not response:
            return None

        work_group = response.get('WorkGroup') or {}
        work_group['arn'] = self._build_arn(region, 'workgroup', name)
        return work_group

    async def _get_data_catalog(self, summary: Dict, region: str) -> Optional[Dict]:
        """Describe one data catalog, falling back on what the listing already said.

        GetDataCatalog reaches out to the connector behind a federated or a Lambda catalog, so it can
        fail for a catalog whose connector is broken or whose Lambda the scanning identity may not
        invoke. Such a catalog is still part of the inventory, and its type and status are the part of
        it a rule would look at, so the summary is kept rather than the catalog dropped."""

        name = summary.get('CatalogName')
        if not name:
            return None

        response = await self._call(region, 'get_data_catalog', Name=name)
        data_catalog = (response or {}).get('DataCatalog') or {
            'Name': name,
            'Type': summary.get('Type'),
            'Status': summary.get('Status'),
            'ConnectionType': summary.get('ConnectionType'),
            'Error': summary.get('Error'),
        }

        data_catalog['arn'] = self._build_arn(region, 'datacatalog', name)
        return data_catalog

    async def _get_and_set_tags(self, entity: Dict, region: str):
        arn = entity.get('arn')
        if not arn:
            return

        tags = await self._get_all_pages(region, 'list_tags_for_resource', 'Tags', ResourceARN=arn)
        entity['tags'] = {tag['Key']: tag.get('Value') for tag in tags if tag.get('Key')}

    def _build_arn(self, region: str, resource_type: str, name: str) -> Optional[str]:
        if not self.partition or not self.owner_id:
            return None

        return format_arn(self.partition, 'athena', region, self.owner_id, name, resource_type)

    async def _call(self, region: str, method_name: str, **args) -> Optional[Dict]:
        client = AWSFacadeUtils.get_client('athena', self.session, region)
        try:
            method = getattr(client, method_name)
            response = await run_concurrently(lambda: method(**args))
        except Exception as e:
            print_exception(f'Failed to call {method_name} on the Athena API '
                            f'for {", ".join(args.values())}: {e}')
            return None

        response.pop('ResponseMetadata', None)
        return response

    async def _get_all_pages(self, region: str, paginator_name: str, entity: str, **args) -> List[Dict]:
        try:
            return await AWSFacadeUtils.get_all_pages(
                'athena', region, self.session, paginator_name, entity, **args)
        except Exception as e:
            print_exception(f'Failed to call {paginator_name} on the Athena API: {e}')
            return []

    async def _list_all(self, region: str, method_name: str, entity: str, **args) -> List[Dict]:
        """Page through a listing botocore does not describe as pageable. ListWorkGroups has no
        paginator on the athena client, so its pages are walked by hand."""

        client = AWSFacadeUtils.get_client('athena', self.session, region)

        entities, next_token = [], None
        while True:
            page_args = dict(args, NextToken=next_token) if next_token else dict(args)
            try:
                method = getattr(client, method_name)
                page = await run_concurrently(lambda arguments=page_args: method(**arguments))
            except Exception as e:
                print_exception(f'Failed to call {method_name} on the Athena API: {e}')
                return entities

            entities.extend(page.get(entity) or [])
            next_token = page.get('NextToken')
            if not next_token:
                return entities
