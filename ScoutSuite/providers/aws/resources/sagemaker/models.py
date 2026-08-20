from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources


class Models(AWSResources):
    """The SageMaker models of a region: the containers, the artifact and the execution role that an
    endpoint, a batch transform job or an inference pipeline runs. A model is a definition rather than
    something running, but it fixes what will run and what it will be allowed to reach."""

    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw_model in await self.facade.sagemaker.get_models(self.region):
            id, model = self._parse_model(raw_model)
            self[id] = model

    def _parse_model(self, raw_model):
        created = raw_model.get('CreationTime')
        vpc_config = raw_model.get('VpcConfig') or {}

        model = {}
        # A model name is unique within a region and account, and is what an endpoint configuration
        # and a transform job refer to
        model['id'] = raw_model['ModelName']
        model['name'] = raw_model['ModelName']
        model['arn'] = raw_model.get('ModelArn')
        model['region'] = self.region
        model['creation_time'] = created.strftime('%Y-%m-%d %H:%M:%S') if created else None
        # The role the containers assume, and therefore what code running inside them may call
        model['execution_role_arn'] = raw_model.get('ExecutionRoleArn')
        # Network isolation cuts the containers off from the network in both directions, so the model
        # can only be reached through SageMaker and cannot call out with the credentials it holds
        model['network_isolation'] = bool(raw_model.get('EnableNetworkIsolation'))
        model['subnets'] = vpc_config.get('Subnets') or []
        model['security_groups'] = vpc_config.get('SecurityGroupIds') or []
        # Without a VPC configuration the containers run in one SageMaker owns, where no security
        # group, route table or VPC endpoint policy of the account applies to their egress
        model['in_customer_vpc'] = bool(model['subnets'])
        # Serial runs the containers as an inference pipeline, Direct as independently addressable
        # containers behind one endpoint
        model['inference_execution_mode'] = (raw_model.get('InferenceExecutionConfig') or {}).get('Mode')

        self._parse_containers(raw_model, model)

        return model['id'], model

    @staticmethod
    def _parse_containers(raw_model, model):
        """The containers the model is made of, and where each takes its image and its artifact from.

        Only the names of the container environment variables are kept: the values are the model's
        own configuration, are frequently used to carry credentials and endpoints, and would end up
        verbatim in a report that is meant to be shareable."""

        raw_containers = raw_model.get('Containers') or []
        primary = raw_model.get('PrimaryContainer')
        if primary:
            raw_containers = [primary] + raw_containers

        containers = []
        for raw_container in raw_containers:
            data_source = raw_container.get('ModelDataSource') or {}
            containers.append({
                'hostname': raw_container.get('ContainerHostname'),
                'image': raw_container.get('Image'),
                # SingleModel, or MultiModel where the container loads artifacts from a prefix on
                # demand rather than one artifact fixed at creation
                'mode': raw_container.get('Mode'),
                'model_data_url': raw_container.get('ModelDataUrl')
                or ((data_source.get('S3DataSource') or {}).get('S3Uri')),
                'model_package_name': raw_container.get('ModelPackageName'),
                # Whether SageMaker checks the image against a private registry over a VPC endpoint
                'image_repository_access_mode':
                    (raw_container.get('ImageConfig') or {}).get('RepositoryAccessMode'),
                'environment_variable_names': sorted((raw_container.get('Environment') or {}).keys()),
            })

        model['containers'] = containers
        model['containers_count'] = len(containers)
        model['images'] = [container['image'] for container in containers if container['image']]
