from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id

# Broker settings MSK applies when a cluster carries no configuration, or a configuration that
# leaves them out. They are not what a hardened cluster would use, so they have to be spelled out
# rather than reported as absent.
# https://docs.aws.amazon.com/msk/latest/developerguide/msk-default-configuration.html
DEFAULT_SERVER_PROPERTIES = {
    'allow.everyone.if.no.acl.found': 'true',
    'auto.create.topics.enable': 'false',
    'unclean.leader.election.enable': 'true',
}


class Clusters(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        raw_clusters = await self.facade.msk.get_clusters(self.region)
        if not raw_clusters:
            return

        kafka_version_statuses = await self.facade.msk.get_kafka_version_statuses(self.region)
        for raw_cluster in raw_clusters:
            name, resource = self._parse_cluster(raw_cluster, kafka_version_statuses)
            await self._parse_encryption_at_rest(raw_cluster, resource)
            self[name] = resource

    def _parse_cluster(self, raw_cluster, kafka_version_statuses):
        creation_time = raw_cluster.get('CreationTime')

        cluster = {}
        cluster['name'] = raw_cluster['ClusterName']
        cluster['arn'] = raw_cluster['ClusterArn']
        cluster['region'] = self.region
        cluster['cluster_type'] = raw_cluster.get('ClusterType', 'PROVISIONED')
        cluster['state'] = raw_cluster.get('State')
        cluster['creation_time'] = creation_time.strftime('%Y-%m-%d %H:%M:%S') if creation_time else None
        # Only set when a cluster policy grants access to other accounts, absent otherwise
        if 'policy' in raw_cluster:
            cluster['policy'] = raw_cluster['policy']

        provisioned = raw_cluster.get('Provisioned') or {}
        serverless = raw_cluster.get('Serverless') or {}

        self._parse_brokers(provisioned, serverless, cluster)
        self._parse_version(provisioned, cluster, kafka_version_statuses)
        self._parse_encryption_in_transit(provisioned, cluster)
        self._parse_authentication(raw_cluster, provisioned, serverless, cluster)
        self._parse_connectivity(provisioned, cluster)
        self._parse_monitoring(provisioned, cluster)
        self._parse_server_properties(raw_cluster, provisioned, cluster)

        return get_non_provider_id(cluster['name']), cluster

    @staticmethod
    def _parse_brokers(provisioned, serverless, cluster):
        broker_info = provisioned.get('BrokerNodeGroupInfo') or {}
        ebs_info = (broker_info.get('StorageInfo') or {}).get('EbsStorageInfo') or {}

        cluster['number_of_broker_nodes'] = provisioned.get('NumberOfBrokerNodes')
        cluster['instance_type'] = broker_info.get('InstanceType')
        cluster['storage_volume_size'] = ebs_info.get('VolumeSize')
        cluster['storage_mode'] = provisioned.get('StorageMode')
        # A serverless cluster carries one VPC configuration per attached VPC, a provisioned one is
        # confined to a single VPC and lists its subnets directly
        if serverless:
            vpc_configs = serverless.get('VpcConfigs') or []
            cluster['client_subnets'] = [subnet for config in vpc_configs
                                         for subnet in config.get('SubnetIds') or []]
            cluster['security_groups'] = [group for config in vpc_configs
                                          for group in config.get('SecurityGroupIds') or []]
            cluster['network_type'] = (serverless.get('ConnectivityInfo') or {}).get('NetworkType')
        else:
            cluster['client_subnets'] = broker_info.get('ClientSubnets') or []
            cluster['security_groups'] = broker_info.get('SecurityGroups') or []
            cluster['network_type'] = (broker_info.get('ConnectivityInfo') or {}).get('NetworkType')

        # ZooKeeper answers on its own endpoints, without authentication unless TLS is configured,
        # and whoever reaches it can rewrite the metadata of every topic. Clusters created as KRaft
        # report none of this.
        cluster['zookeeper_connect_string'] = provisioned.get('ZookeeperConnectString')
        cluster['zookeeper_connect_string_tls'] = provisioned.get('ZookeeperConnectStringTls')

    @staticmethod
    def _parse_version(provisioned, cluster, kafka_version_statuses):
        software_info = provisioned.get('CurrentBrokerSoftwareInfo') or {}
        version = software_info.get('KafkaVersion')

        cluster['kafka_version'] = version
        cluster['configuration_arn'] = software_info.get('ConfigurationArn')
        cluster['configuration_revision'] = software_info.get('ConfigurationRevision')

        # MSK is the authority on which versions it still supports, so the status is read from the
        # API rather than from a transcribed calendar. A serverless cluster runs a version AWS picks
        # and does not report, and an unknown version is left undecided.
        status = kafka_version_statuses.get(version) if version else None
        cluster['kafka_version_status'] = status
        cluster['kafka_version_deprecated'] = status == 'DEPRECATED' if status else None

    @staticmethod
    def _parse_encryption_in_transit(provisioned, cluster):
        # Serverless clusters are TLS only, in both directions, with nothing to configure
        if not provisioned:
            cluster['encryption_in_transit_client_broker'] = 'TLS'
            cluster['client_broker_plaintext_allowed'] = False
            cluster['client_broker_plaintext_only'] = False
            cluster['encryption_in_cluster'] = True
            return

        in_transit = (provisioned.get('EncryptionInfo') or {}).get('EncryptionInTransit') or {}
        # TLS_PLAINTEXT lets a client pick either, so a misconfigured or downgraded producer sends
        # records, and its credentials when SASL/SCRAM is used, in the clear over the VPC
        client_broker = in_transit.get('ClientBroker', 'TLS')

        cluster['encryption_in_transit_client_broker'] = client_broker
        cluster['client_broker_plaintext_allowed'] = client_broker in ('PLAINTEXT', 'TLS_PLAINTEXT')
        cluster['client_broker_plaintext_only'] = client_broker == 'PLAINTEXT'
        cluster['encryption_in_cluster'] = in_transit.get('InCluster', True)

    async def _parse_encryption_at_rest(self, raw_cluster, cluster):
        at_rest = ((raw_cluster.get('Provisioned') or {}).get('EncryptionInfo') or {}).get('EncryptionAtRest') or {}
        key_id = at_rest.get('DataVolumeKMSKeyId')

        cluster['encryption_at_rest_kms_key'] = key_id
        if not key_id:
            # Serverless clusters do not report a key, and are encrypted with one the account does
            # not manage either way
            cluster['encryption_at_rest_with_cmk'] = None if cluster['cluster_type'] == 'SERVERLESS' else False
            return

        key_manager = await self.facade.msk.get_key_manager(self.region, key_id)
        cluster['encryption_at_rest_with_cmk'] = key_manager == 'CUSTOMER' if key_manager else None

    @staticmethod
    def _parse_authentication(raw_cluster, provisioned, serverless, cluster):
        client_authentication = (provisioned or serverless).get('ClientAuthentication') or {}
        sasl = client_authentication.get('Sasl') or {}

        cluster['iam_authentication_enabled'] = bool((sasl.get('Iam') or {}).get('Enabled'))
        cluster['scram_authentication_enabled'] = bool((sasl.get('Scram') or {}).get('Enabled'))
        cluster['tls_authentication_enabled'] = bool((client_authentication.get('Tls') or {}).get('Enabled'))
        cluster['tls_certificate_authorities'] = \
            (client_authentication.get('Tls') or {}).get('CertificateAuthorityArnList') or []
        # Serverless clusters cannot be opened to unauthenticated clients
        cluster['unauthenticated_access_enabled'] = \
            bool((client_authentication.get('Unauthenticated') or {}).get('Enabled'))

        # A provisioned cluster with no authentication block at all is an unauthenticated cluster:
        # MSK creates one that way when the request leaves ClientAuthentication out
        if provisioned and not client_authentication:
            cluster['unauthenticated_access_enabled'] = True

        cluster['authentication_methods'] = [
            name for name, enabled in (
                ('SASL/IAM', cluster['iam_authentication_enabled']),
                ('SASL/SCRAM', cluster['scram_authentication_enabled']),
                ('mTLS', cluster['tls_authentication_enabled']),
                ('Unauthenticated', cluster['unauthenticated_access_enabled']),
            ) if enabled
        ]

        # SASL/SCRAM answers with the credentials held in the secrets associated with the cluster,
        # so the mechanism accepts nobody until at least one is attached
        scram_secrets = raw_cluster.get('scram_secrets')
        cluster['scram_secrets_count'] = len(scram_secrets) if scram_secrets is not None else None

    @staticmethod
    def _parse_connectivity(provisioned, cluster):
        # A serverless cluster reaches none of these, it is only ever reachable from its VPCs
        connectivity = (provisioned.get('BrokerNodeGroupInfo') or {}).get('ConnectivityInfo') or {}
        # DISABLED is the only other value, SERVICE_PROVIDED_EIPS means each broker answers on a
        # public elastic IP
        public_access_type = (connectivity.get('PublicAccess') or {}).get('Type')

        cluster['public_access_type'] = public_access_type
        cluster['public_access_enabled'] = \
            bool(public_access_type) and public_access_type != 'DISABLED'

        # Private connectivity offered to clients in other VPCs, and possibly other accounts when a
        # cluster policy allows it
        vpc_connectivity = (connectivity.get('VpcConnectivity') or {}).get('ClientAuthentication') or {}
        vpc_sasl = vpc_connectivity.get('Sasl') or {}
        cluster['vpc_connectivity_iam_enabled'] = bool((vpc_sasl.get('Iam') or {}).get('Enabled'))
        cluster['vpc_connectivity_scram_enabled'] = bool((vpc_sasl.get('Scram') or {}).get('Enabled'))
        cluster['vpc_connectivity_tls_enabled'] = bool((vpc_connectivity.get('Tls') or {}).get('Enabled'))
        cluster['vpc_connectivity_enabled'] = any([cluster['vpc_connectivity_iam_enabled'],
                                                   cluster['vpc_connectivity_scram_enabled'],
                                                   cluster['vpc_connectivity_tls_enabled']])

    @staticmethod
    def _parse_monitoring(provisioned, cluster):
        broker_logs = (provisioned.get('LoggingInfo') or {}).get('BrokerLogs') or {}
        cloudwatch_logs = broker_logs.get('CloudWatchLogs') or {}
        firehose = broker_logs.get('Firehose') or {}
        s3 = broker_logs.get('S3') or {}

        cluster['broker_logs_cloudwatch_enabled'] = bool(cloudwatch_logs.get('Enabled'))
        cluster['broker_logs_cloudwatch_log_group'] = cloudwatch_logs.get('LogGroup')
        cluster['broker_logs_firehose_enabled'] = bool(firehose.get('Enabled'))
        cluster['broker_logs_firehose_delivery_stream'] = firehose.get('DeliveryStream')
        cluster['broker_logs_s3_enabled'] = bool(s3.get('Enabled'))
        cluster['broker_logs_s3_bucket'] = s3.get('Bucket')
        # Serverless clusters have no broker logs to deliver at all
        cluster['broker_logs_enabled'] = any([cluster['broker_logs_cloudwatch_enabled'],
                                              cluster['broker_logs_firehose_enabled'],
                                              cluster['broker_logs_s3_enabled']])

        # DEFAULT only publishes cluster level metrics, which is not enough to tell a broker apart
        # from another when investigating
        enhanced_monitoring = provisioned.get('EnhancedMonitoring')
        cluster['enhanced_monitoring'] = enhanced_monitoring
        cluster['enhanced_monitoring_enabled'] = \
            enhanced_monitoring != 'DEFAULT' if enhanced_monitoring else None

        prometheus = (provisioned.get('OpenMonitoring') or {}).get('Prometheus') or {}
        cluster['open_monitoring_jmx_exporter_enabled'] = \
            bool((prometheus.get('JmxExporter') or {}).get('EnabledInBroker'))
        cluster['open_monitoring_node_exporter_enabled'] = \
            bool((prometheus.get('NodeExporter') or {}).get('EnabledInBroker'))

    @staticmethod
    def _parse_server_properties(raw_cluster, provisioned, cluster):
        """Read the broker settings that decide who may reach a topic. They are only meaningful on a
        provisioned cluster: a serverless one has no configuration and is IAM only."""

        if not provisioned:
            cluster['server_properties'] = {}
            cluster['acl_default_allow'] = None
            cluster['acl_default_allow_effective'] = None
            cluster['auto_create_topics_enabled'] = None
            cluster['unclean_leader_election_enabled'] = None
            return

        properties = dict(DEFAULT_SERVER_PROPERTIES)
        properties.update(raw_cluster.get('server_properties') or {})

        cluster['server_properties'] = properties
        cluster['acl_default_allow'] = properties['allow.everyone.if.no.acl.found'].lower() == 'true'
        cluster['auto_create_topics_enabled'] = properties['auto.create.topics.enable'].lower() == 'true'
        cluster['unclean_leader_election_enabled'] = \
            properties['unclean.leader.election.enable'].lower() == 'true'

        # Kafka ACLs, and therefore the setting that governs what happens in their absence, are only
        # consulted for clients that authenticated with mTLS or SASL/SCRAM or not at all. Access
        # granted through SASL/IAM is decided by IAM policies instead.
        cluster['acl_default_allow_effective'] = cluster['acl_default_allow'] and any([
            cluster['tls_authentication_enabled'],
            cluster['scram_authentication_enabled'],
            cluster['unauthenticated_access_enabled'],
        ])
