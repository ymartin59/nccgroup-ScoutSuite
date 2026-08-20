from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources


class TrainingJobs(AWSResources):
    """The most recent SageMaker training jobs of a region.

    A training job is the point in the machine learning lifecycle where the raw training data, the
    training code and an IAM role able to read both meet on instances SageMaker provisions. The job
    is short lived and cannot be reconfigured once it has run, so what a finding on one says is not
    "fix this job" but "this is how this account trains", which is the thing a template, a pipeline or
    an SDK call has to be changed to alter. Only the newest jobs are collected, since a job record is
    kept for ever and the old ones describe practices already replaced."""

    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw_training_job in await self.facade.sagemaker.get_training_jobs(self.region):
            id, training_job = self._parse_training_job(raw_training_job)
            self[id] = training_job

    def _parse_training_job(self, raw_training_job):
        created = raw_training_job.get('CreationTime')
        ended = raw_training_job.get('TrainingEndTime')
        vpc_config = raw_training_job.get('VpcConfig') or {}
        output_config = raw_training_job.get('OutputDataConfig') or {}
        resource_config = raw_training_job.get('ResourceConfig') or {}

        training_job = {}
        # A training job name is unique within a region and account, and is what the console, the
        # metrics and the model artifact path are keyed on
        training_job['id'] = raw_training_job['TrainingJobName']
        training_job['name'] = raw_training_job['TrainingJobName']
        training_job['arn'] = raw_training_job.get('TrainingJobArn')
        training_job['region'] = self.region
        training_job['status'] = raw_training_job.get('TrainingJobStatus')
        training_job['secondary_status'] = raw_training_job.get('SecondaryStatus')
        training_job['creation_time'] = created.strftime('%Y-%m-%d %H:%M:%S') if created else None
        training_job['end_time'] = ended.strftime('%Y-%m-%d %H:%M:%S') if ended else None
        # The role the training containers assume, which is what reads the input data and writes the
        # model artifact, and what code shipped in a training image would run as
        training_job['role_arn'] = raw_training_job.get('RoleArn')
        # Set when the job was created by a tuning, labelling or AutoML job rather than directly,
        # in which case the settings come from that parent and not from a call anybody made
        training_job['tuning_job_arn'] = raw_training_job.get('TuningJobArn')
        training_job['auto_ml_job_arn'] = raw_training_job.get('AutoMLJobArn')
        training_job['labeling_job_arn'] = raw_training_job.get('LabelingJobArn')

        algorithm = raw_training_job.get('AlgorithmSpecification') or {}
        training_job['training_image'] = algorithm.get('TrainingImage')
        training_job['algorithm_name'] = algorithm.get('AlgorithmName')

        # Network isolation cuts the training containers off from the network, so a training image -
        # frequently a third-party or community one - cannot reach out from inside the account with
        # the role it runs as, nor send the training data anywhere
        training_job['network_isolation'] = bool(raw_training_job.get('EnableNetworkIsolation'))
        training_job['subnets'] = vpc_config.get('Subnets') or []
        training_job['security_groups'] = vpc_config.get('SecurityGroupIds') or []
        # Without a VPC configuration the job runs in a VPC SageMaker owns, where no security group,
        # route table or VPC endpoint policy of the account governs its egress and no flow log
        # records it
        training_job['in_customer_vpc'] = bool(training_job['subnets'])

        self._parse_encryption(raw_training_job, training_job, output_config, resource_config)
        self._parse_resources(training_job, resource_config)
        self._parse_data(raw_training_job, training_job, output_config)

        return training_job['id'], training_job

    @staticmethod
    def _parse_encryption(raw_training_job, training_job, output_config, resource_config):
        """The three places a training job holds the data it was given.

        The output location receives the model artifact, which is a function of the training data and
        can be inverted far enough to be treated as holding it. The storage volume of each instance
        receives the downloaded training data and the checkpoints. Both are always encrypted, so what
        matters is whose key. Inter-container traffic is the third: on a job spread over several
        instances the training data crosses the network between them, and SageMaker only encrypts
        that traffic when asked."""

        output_kms_key_id = output_config.get('KmsKeyId')
        volume_kms_key_id = resource_config.get('VolumeKmsKeyId')

        training_job['output_kms_key_id'] = output_kms_key_id
        training_job['output_encrypted_with_cmk'] = bool(output_kms_key_id)
        training_job['volume_kms_key_id'] = volume_kms_key_id
        training_job['volume_encrypted_with_cmk'] = bool(volume_kms_key_id)
        training_job['inter_container_traffic_encryption'] = \
            bool(raw_training_job.get('EnableInterContainerTrafficEncryption'))

    @staticmethod
    def _parse_resources(training_job, resource_config):
        """The instances the job ran on. A job declares either one instance type and a count, or
        heterogeneous instance groups, and only the total decides whether there was any traffic
        between containers to encrypt."""

        instance_groups = resource_config.get('InstanceGroups') or []

        training_job['instance_type'] = resource_config.get('InstanceType')
        training_job['instance_groups'] = [
            {
                'name': group.get('InstanceGroupName'),
                'instance_type': group.get('InstanceType'),
                'instance_count': group.get('InstanceCount'),
            }
            for group in instance_groups
        ]
        training_job['instance_count'] = resource_config.get('InstanceCount') or sum(
            group.get('InstanceCount') or 0 for group in instance_groups)
        # A job on a single instance has no traffic between containers, so inter-container encryption
        # decides nothing for it
        training_job['distributed'] = training_job['instance_count'] > 1
        training_job['volume_size'] = resource_config.get('VolumeSizeInGB')

    @staticmethod
    def _parse_data(raw_training_job, training_job, output_config):
        """Where the job read from and wrote to, by location only. The hyperparameters are values the
        caller chose and are a documented place for a token or a URL to be passed to training code,
        so only their names are kept."""

        training_job['output_s3_path'] = output_config.get('S3OutputPath')
        training_job['model_artifact'] = \
            (raw_training_job.get('ModelArtifacts') or {}).get('S3ModelArtifacts')
        training_job['input_channels'] = [
            {
                'name': channel.get('ChannelName'),
                's3_uri': ((channel.get('DataSource') or {}).get('S3DataSource') or {}).get('S3Uri'),
                'file_system_id':
                    ((channel.get('DataSource') or {}).get('FileSystemDataSource') or {}).get('FileSystemId'),
            }
            for channel in raw_training_job.get('InputDataConfig') or []
        ]
        training_job['hyperparameter_names'] = sorted((raw_training_job.get('HyperParameters') or {}).keys())
        training_job['environment_variable_names'] = sorted((raw_training_job.get('Environment') or {}).keys())
