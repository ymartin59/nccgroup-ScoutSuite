from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.utils import get_name, format_arn


class RegionalSettings(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region
        self.partition = facade.partition
        self.service = 'ec2'
        self.resource_type = 'regional_setting'

    async def fetch_all(self):
        # These settings are associated directly with the service+region, not with any resource.
        # However, ScoutSuite seems to assume that every setting is tied to a resource so we make 
        # up a fake resource to hold them.
        self[0] = {}
        self[0]['ebs_encryption_default'] = (await self.facade.ec2.get_ebs_encryption(self.region))['EbsEncryptionByDefault']
        self[0]['ebs_default_encryption_key_id'] = (await self.facade.ec2.get_ebs_default_encryption_key(self.region))['KmsKeyId']

        # What an instance launched without any metadata option of its own gets in this region. It
        # is what decides the metadata service exposure of every launch template and launch
        # configuration that leaves the setting out.
        metadata_defaults = await self.facade.ec2.get_instance_metadata_defaults(self.region)
        self[0]['instance_metadata_defaults'] = metadata_defaults
        self[0]['instance_metadata_default_http_tokens'] = metadata_defaults.get('HttpTokens')
        self[0]['instance_metadata_default_hop_limit'] = metadata_defaults.get('HttpPutResponseHopLimit')
        self[0]['instance_metadata_defaults_require_imdsv2'] = metadata_defaults.get('HttpTokens') == 'required'
        # One hop reaches the instance and nothing else. Beyond that the metadata service, and the
        # credentials of the instance profile it hands out, answer containers and any process able to
        # make the instance forward a request. A hop limit of -1 means no account-level preference.
        hop_limit = metadata_defaults.get('HttpPutResponseHopLimit')
        self[0]['instance_metadata_defaults_hop_limit_excessive'] = \
            hop_limit is not None and hop_limit > 1

        # A region-wide refusal to share EBS snapshots publicly, which holds whatever the permissions
        # of an individual snapshot say, including the ones created after it was turned on.
        state = await self.facade.ec2.get_snapshot_block_public_access_state(self.region)
        self[0]['snapshot_block_public_access_state'] = state
        self[0]['snapshot_public_sharing_blocked'] = state in ('block-all-sharing', 'block-new-sharing')
        self[0]['snapshot_public_sharing_fully_blocked'] = state == 'block-all-sharing'
