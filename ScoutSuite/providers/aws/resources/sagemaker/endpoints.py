from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources


class Endpoints(AWSResources):
    """The SageMaker inference endpoints of a region: a long-lived HTTPS entry point, reached through
    the SageMaker runtime API and authorized by IAM, in front of one or more model containers."""

    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw_endpoint in await self.facade.sagemaker.get_endpoints(self.region):
            id, endpoint = self._parse_endpoint(raw_endpoint)
            self[id] = endpoint

    def _parse_endpoint(self, raw_endpoint):
        created = raw_endpoint.get('CreationTime')
        modified = raw_endpoint.get('LastModifiedTime')

        endpoint = {}
        # An endpoint name is unique within a region and account, and is what the runtime API takes
        endpoint['id'] = raw_endpoint['EndpointName']
        endpoint['name'] = raw_endpoint['EndpointName']
        endpoint['arn'] = raw_endpoint.get('EndpointArn')
        endpoint['region'] = self.region
        endpoint['status'] = raw_endpoint.get('EndpointStatus')
        endpoint['failure_reason'] = raw_endpoint.get('FailureReason')
        endpoint['creation_time'] = created.strftime('%Y-%m-%d %H:%M:%S') if created else None
        endpoint['last_modified_time'] = modified.strftime('%Y-%m-%d %H:%M:%S') if modified else None
        endpoint['endpoint_config_name'] = raw_endpoint.get('EndpointConfigName')

        self._parse_configuration(raw_endpoint, endpoint)
        self._parse_variants(raw_endpoint, endpoint)
        self._parse_data_capture(raw_endpoint, endpoint)

        return endpoint['id'], endpoint

    @staticmethod
    def _parse_configuration(raw_endpoint, endpoint):
        """The settings the endpoint serves under, which live in its endpoint configuration and not on
        the endpoint itself.

        The volume key protects the ML storage volume of the hosting instances, where the model
        artifact is unpacked and where anything the container writes lands. Network isolation cuts
        the containers off from the network entirely, so an endpoint that only has to answer requests
        cannot call out; the VPC configuration decides what it may reach when it is not isolated.

        A configuration that could not be read leaves all of this unknown rather than reported as
        absent, since a denied DescribeEndpointConfig would otherwise look like an unencrypted
        endpoint."""

        config = raw_endpoint.get('endpoint_config')
        if config is None:
            endpoint['kms_key_id'] = None
            endpoint['encryption_with_cmk'] = None
            endpoint['network_isolation'] = None
            endpoint['subnets'] = []
            endpoint['security_groups'] = []
            endpoint['in_customer_vpc'] = None
            endpoint['execution_role_arn'] = None
            return

        kms_key_id = config.get('KmsKeyId')
        vpc_config = config.get('VpcConfig') or {}

        endpoint['kms_key_id'] = kms_key_id
        endpoint['encryption_with_cmk'] = bool(kms_key_id)
        endpoint['network_isolation'] = bool(config.get('EnableNetworkIsolation'))
        endpoint['subnets'] = vpc_config.get('Subnets') or []
        endpoint['security_groups'] = vpc_config.get('SecurityGroupIds') or []
        endpoint['in_customer_vpc'] = bool(endpoint['subnets'])
        endpoint['execution_role_arn'] = config.get('ExecutionRoleArn')

    @staticmethod
    def _parse_variants(raw_endpoint, endpoint):
        """The production variants the endpoint splits its traffic between, and the shadow variants it
        mirrors a copy of that traffic to.

        A variant is either instance backed, where the instance count is what stands between the
        endpoint and the loss of an Availability Zone, or serverless, where SageMaker provides the
        capacity and there is nothing to count."""

        config = raw_endpoint.get('endpoint_config') or {}
        declared_variants = (config.get('ProductionVariants') or []) + \
            (config.get('ShadowProductionVariants') or [])
        # The model each variant serves is named by the endpoint configuration, not by the endpoint
        configured = {variant['VariantName']: variant for variant in declared_variants
                      if variant.get('VariantName')}

        raw_variants = (raw_endpoint.get('ProductionVariants') or []) + \
            (raw_endpoint.get('ShadowProductionVariants') or [])

        variants = {}
        for raw_variant in raw_variants:
            name = raw_variant.get('VariantName')
            if not name:
                continue

            declared = configured.get(name) or {}
            serverless = raw_variant.get('CurrentServerlessConfig') or declared.get('ServerlessConfig')
            instance_count = raw_variant.get('CurrentInstanceCount')

            variants[name] = {
                'id': name,
                'name': name,
                'model_name': declared.get('ModelName'),
                'instance_type': raw_variant.get('InstanceType') or declared.get('InstanceType'),
                'instance_count': instance_count,
                'desired_instance_count': raw_variant.get('DesiredInstanceCount'),
                'serverless': bool(serverless),
                'current_weight': raw_variant.get('CurrentWeight'),
                # A serverless variant has no instances, so it is never a single point of failure;
                # a variant whose instance count the API did not report leaves this unknown
                'single_instance': None if serverless or instance_count is None else instance_count < 2,
                'images': [image.get('ResolvedImage') or image.get('SpecifiedImage')
                           for image in raw_variant.get('DeployedImages') or []],
            }

        endpoint['production_variants'] = variants
        endpoint['production_variants_count'] = len(variants)

    @staticmethod
    def _parse_data_capture(raw_endpoint, endpoint):
        """Data capture writes the requests and the responses the endpoint handles to S3, verbatim.

        That is the inference payloads themselves, so the destination holds whatever callers send the
        model - and a capture destination written with a key AWS manages cannot be revoked or made
        auditable by the account that owns the data in it."""

        capture = raw_endpoint.get('DataCaptureConfig') or {}
        configured = (raw_endpoint.get('endpoint_config') or {}).get('DataCaptureConfig') or {}

        enabled = bool(capture.get('EnableCapture', configured.get('EnableCapture')))
        kms_key_id = capture.get('KmsKeyId') or configured.get('KmsKeyId')

        endpoint['data_capture_enabled'] = enabled
        endpoint['data_capture_status'] = capture.get('CaptureStatus')
        endpoint['data_capture_destination'] = \
            capture.get('DestinationS3Uri') or configured.get('DestinationS3Uri')
        endpoint['data_capture_kms_key_id'] = kms_key_id
        endpoint['data_capture_sampling_percentage'] = \
            capture.get('CurrentSamplingPercentage', configured.get('InitialSamplingPercentage'))
        # What the capture records: the request, the response, or both
        endpoint['data_capture_options'] = [option.get('CaptureMode')
                                           for option in configured.get('CaptureOptions') or []]
        # Only decided for an endpoint that captures anything: there is nothing to encrypt otherwise
        endpoint['data_capture_encrypted_with_cmk'] = bool(kms_key_id) if enabled else None
