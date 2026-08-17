from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id

SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'UNDEFINED']


class Images(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        raw_repositories = await self.facade.ecr.get_repositories(self.region)
        for raw_repository in raw_repositories:
            repository_name = raw_repository.get('repositoryName')
            if not repository_name:
                continue
            raw_images = await self.facade.ecr.get_images(self.region, repository_name)
            for raw_image in raw_images:
                name, resource = self._parse_image(raw_image)
                self[name] = resource

    def _parse_image(self, raw_image):
        image = {}
        repository_name = raw_image['repositoryName']
        image_digest = raw_image['imageDigest']
        image_tags = raw_image.get('imageTags', [])

        # The same image may well be pushed to several repositories of the region, so the digest alone
        # does not identify it. Tags do not either, an image may carry none.
        image['id'] = get_non_provider_id('{}@{}'.format(repository_name, image_digest))
        image['name'] = '{}:{}'.format(repository_name, ', '.join(image_tags)) if image_tags \
            else '{}@{}'.format(repository_name, image_digest)
        image['repository_name'] = repository_name
        image['registry_id'] = raw_image.get('registryId')
        image['image_digest'] = image_digest
        image['image_tags'] = image_tags
        image['image_size_in_bytes'] = raw_image.get('imageSizeInBytes')
        image['artifact_media_type'] = raw_image.get('artifactMediaType')
        image['region'] = self.region
        pushed_at = raw_image.get('imagePushedAt')
        image['pushed_at'] = pushed_at.strftime('%Y-%m-%d %H:%M:%S') if pushed_at else None

        self._parse_scan_findings(raw_image, image)

        return image['id'], image

    @staticmethod
    def _parse_scan_findings(raw_image, image):
        scan_status = raw_image.get('imageScanStatus') or {}
        image['scan_status'] = scan_status.get('status')
        image['scan_status_description'] = scan_status.get('description')
        # An image is only reported as scanned once findings exist for it, which is not the same as the
        # repository having scanning configured: images pushed before it was turned on stay unscanned
        image['scanned'] = scan_status.get('status') == 'COMPLETE'

        scan_findings = raw_image.get('imageScanFindings') or {}
        completed_at = scan_findings.get('imageScanCompletedAt')
        image['scan_completed_at'] = completed_at.strftime('%Y-%m-%d %H:%M:%S') if completed_at else None

        severity_counts = scan_findings.get('findingSeverityCounts', {})
        image['finding_severity_counts'] = severity_counts
        for severity in SEVERITIES:
            image['{}_severity_count'.format(severity.lower())] = severity_counts.get(severity, 0)
