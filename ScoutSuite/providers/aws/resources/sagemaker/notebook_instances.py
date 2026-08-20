from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources


class NotebookInstances(AWSResources):
    """The SageMaker notebook instances of a region: a managed EC2 instance running Jupyter, holding
    an IAM role and, in practice, the data a data scientist pulled down to look at."""

    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw_notebook_instance in await self.facade.sagemaker.get_notebook_instances(self.region):
            id, notebook_instance = self._parse_notebook_instance(raw_notebook_instance)
            self[id] = notebook_instance

    def _parse_notebook_instance(self, raw_notebook_instance):
        created = raw_notebook_instance.get('CreationTime')
        modified = raw_notebook_instance.get('LastModifiedTime')

        notebook_instance = {}
        # A notebook instance name is unique within a region and account, and is what every other
        # SageMaker API call takes, so it is also what the report and the findings refer to
        notebook_instance['id'] = raw_notebook_instance['NotebookInstanceName']
        notebook_instance['name'] = raw_notebook_instance['NotebookInstanceName']
        notebook_instance['arn'] = raw_notebook_instance.get('NotebookInstanceArn')
        notebook_instance['region'] = self.region
        notebook_instance['status'] = raw_notebook_instance.get('NotebookInstanceStatus')
        notebook_instance['failure_reason'] = raw_notebook_instance.get('FailureReason')
        notebook_instance['instance_type'] = raw_notebook_instance.get('InstanceType')
        notebook_instance['platform_identifier'] = raw_notebook_instance.get('PlatformIdentifier')
        notebook_instance['volume_size'] = raw_notebook_instance.get('VolumeSizeInGB')
        notebook_instance['creation_time'] = created.strftime('%Y-%m-%d %H:%M:%S') if created else None
        notebook_instance['last_modified_time'] = modified.strftime('%Y-%m-%d %H:%M:%S') if modified else None
        # The Jupyter URL, which is only reachable through a presigned URL or the console
        notebook_instance['url'] = raw_notebook_instance.get('Url')
        # The role the notebook assumes, and therefore what any code executed in a cell may call
        notebook_instance['role_arn'] = raw_notebook_instance.get('RoleArn')
        # A shell script SageMaker runs as root on creation or on every start, outside the notebook
        notebook_instance['lifecycle_config_name'] = \
            raw_notebook_instance.get('NotebookInstanceLifecycleConfigName')

        self._parse_network(raw_notebook_instance, notebook_instance)
        self._parse_encryption(raw_notebook_instance, notebook_instance)
        self._parse_access(raw_notebook_instance, notebook_instance)
        self._parse_code_repositories(raw_notebook_instance, notebook_instance)

        return notebook_instance['id'], notebook_instance

    @staticmethod
    def _parse_network(raw_notebook_instance, notebook_instance):
        """Where the notebook is attached and what it may reach from there.

        A notebook created without a subnet runs in a VPC SageMaker owns, which no security group,
        route table or network ACL of the account governs and no VPC flow log records. Direct
        internet access is a second, separate switch: SageMaker attaches a network interface with a
        public route of its own, so the notebook reaches the internet whichever VPC it sits in and
        whatever the route table of its subnet says."""

        subnet_id = raw_notebook_instance.get('SubnetId')

        notebook_instance['subnet_id'] = subnet_id
        notebook_instance['in_customer_vpc'] = bool(subnet_id)
        notebook_instance['security_groups'] = raw_notebook_instance.get('SecurityGroups') or []
        notebook_instance['network_interface_id'] = raw_notebook_instance.get('NetworkInterfaceId')
        notebook_instance['ip_address_type'] = raw_notebook_instance.get('IpAddressType')

        # Enabled is what SageMaker applies when the creation request says nothing, and the setting
        # cannot be changed on a running notebook
        direct_internet_access = raw_notebook_instance.get('DirectInternetAccess')
        notebook_instance['direct_internet_access'] = direct_internet_access
        notebook_instance['direct_internet_access_enabled'] = direct_internet_access != 'Disabled'

    @staticmethod
    def _parse_encryption(raw_notebook_instance, notebook_instance):
        """SageMaker always encrypts the ML storage volume of a notebook, so what is worth reporting
        is whose key it uses. A notebook created without a key gets one AWS manages, whose policy the
        account cannot change and whose use it cannot deny."""

        kms_key_id = raw_notebook_instance.get('KmsKeyId')

        notebook_instance['kms_key_id'] = kms_key_id
        notebook_instance['encryption_with_cmk'] = bool(kms_key_id)

    @staticmethod
    def _parse_access(raw_notebook_instance, notebook_instance):
        """The two ways the notebook's own credentials are reachable from a cell.

        Root access lets the notebook user become root on the instance, which puts the lifecycle
        configuration, the installed packages and anything a lifecycle script left on disk under
        their control. The instance metadata service hands out the credentials of the notebook's IAM
        role, and IMDSv1 hands them to any request that reaches it, including one made on the user's
        behalf by a notebook opened from elsewhere."""

        root_access = raw_notebook_instance.get('RootAccess')
        notebook_instance['root_access'] = root_access
        # Enabled is what SageMaker applies when the creation request says nothing
        notebook_instance['root_access_enabled'] = root_access != 'Disabled'

        imds = raw_notebook_instance.get('InstanceMetadataServiceConfiguration') or {}
        minimum_version = imds.get('MinimumInstanceMetadataServiceVersion')
        notebook_instance['imds_minimum_version'] = minimum_version
        # A notebook on a platform identifier that predates the setting reports no configuration at
        # all, and answers IMDSv1 requests
        notebook_instance['imdsv2_required'] = minimum_version == '2'

    @staticmethod
    def _parse_code_repositories(raw_notebook_instance, notebook_instance):
        """The Git repositories SageMaker clones into the notebook on every start. Each is either a
        SageMaker code repository of the account, holding the Secrets Manager secret its credentials
        live in, or a public URL cloned without any."""

        default_repository = raw_notebook_instance.get('DefaultCodeRepository')

        notebook_instance['default_code_repository'] = default_repository
        notebook_instance['additional_code_repositories'] = \
            raw_notebook_instance.get('AdditionalCodeRepositories') or []
        notebook_instance['code_repositories'] = \
            ([default_repository] if default_repository else []) + \
            notebook_instance['additional_code_repositories']
