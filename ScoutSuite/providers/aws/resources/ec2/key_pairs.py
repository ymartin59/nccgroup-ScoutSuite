from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.utils import format_arn


class KeyPairs(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region
        self.partition = facade.partition
        self.service = 'ec2'
        self.resource_type = 'key-pair'

    async def fetch_all(self):
        raw_key_pairs = await self.facade.ec2.get_key_pairs(self.region)
        for raw_key_pair in raw_key_pairs:
            id, key_pair = self._parse_key_pair(raw_key_pair)
            self[id] = key_pair

    def _parse_key_pair(self, raw_key_pair):
        key_pair = {}
        key_pair['id'] = raw_key_pair.get('KeyPairId')
        key_pair['name'] = raw_key_pair.get('KeyName')
        key_pair['arn'] = format_arn(self.partition, self.service, self.region,
                                     self.facade.owner_id, key_pair['name'], self.resource_type)
        key_pair['key_type'] = raw_key_pair.get('KeyType')
        key_pair['key_fingerprint'] = raw_key_pair.get('KeyFingerprint')
        key_pair['tags'] = raw_key_pair.get('Tags')

        # The date the key pair was registered with AWS. A key pair cannot be rotated in place, so it
        # is also the age of the private key that has been in circulation ever since.
        create_time = raw_key_pair.get('CreateTime')
        key_pair['create_time'] = str(create_time) if create_time else None

        # Filled in during preprocessing, the resources referring to a key pair being spread over the
        # instances, the launch templates and the launch configurations
        key_pair['instances'] = []
        key_pair['used'] = False

        return key_pair['id'], key_pair
