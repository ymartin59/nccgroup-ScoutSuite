from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id

# A data catalog whose status names a failure is a catalog Athena registered but cannot use. It still
# holds whatever the registration pointed at, so it stays in the inventory.
FAILED_STATUSES = ('CREATE_FAILED', 'CREATE_FAILED_CLEANUP_IN_PROGRESS', 'CREATE_FAILED_CLEANUP_COMPLETE',
                   'CREATE_FAILED_CLEANUP_FAILED', 'DELETE_FAILED')


class DataCatalogs(AWSResources):
    """The data catalogs registered in a region, which is the list of places Athena knows how to read
    tables from.

    `AwsDataCatalog` is the Glue Data Catalog of the account and is always present. Anything else is a
    catalog somebody registered: a Hive metastore or a federated source reached through a Lambda
    connector, or a managed connection to another database. Each one widens what a query under this
    account can read to data the account does not hold, and the connector - not Athena - is what
    authenticates to it."""

    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw_data_catalog in await self.facade.athena.get_data_catalogs(self.region):
            id, data_catalog = self._parse_data_catalog(raw_data_catalog)
            self[id] = data_catalog

    def _parse_data_catalog(self, raw_data_catalog):
        name = raw_data_catalog.get('Name')
        catalog_type = raw_data_catalog.get('Type')
        status = raw_data_catalog.get('Status')

        data_catalog = {}
        # A catalog name may contain dots, which the recursion the rule engine walks the config with
        # would read as levels, so the name is hashed into the id and kept beside it
        data_catalog['id'] = get_non_provider_id(name) if name else None
        data_catalog['name'] = name
        data_catalog['arn'] = raw_data_catalog.get('arn')
        data_catalog['region'] = self.region
        data_catalog['description'] = raw_data_catalog.get('Description')
        # GLUE is the Data Catalog of the account; HIVE an external metastore and LAMBDA a federated
        # source, both reached through a Lambda function the account runs; FEDERATED a connection
        # Athena provisions and manages the connector for
        data_catalog['type'] = catalog_type
        data_catalog['status'] = status
        data_catalog['failed'] = status in FAILED_STATUSES
        # The engine behind a FEDERATED catalog, which names the external database the queries reach
        data_catalog['connection_type'] = raw_data_catalog.get('ConnectionType')
        data_catalog['error'] = raw_data_catalog.get('Error')
        # A catalog that is not the Glue Data Catalog reads through code, and the parameters are where
        # the function and the connection it reads through are named
        data_catalog['external'] = catalog_type is not None and catalog_type != 'GLUE'
        # The registration parameters, which Athena documents as the connector function ARNs, the
        # Glue catalog id or the connection ARN - identifiers rather than credentials, which for a
        # federated source live in the Secrets Manager secret the connector is given
        data_catalog['parameters'] = raw_data_catalog.get('Parameters') or {}
        data_catalog['tags'] = raw_data_catalog.get('tags') or {}

        return data_catalog['id'], data_catalog
