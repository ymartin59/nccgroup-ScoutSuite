import unittest

from ScoutSuite.providers.aws.resources.account.region_opt_status import RegionOptStatus


def parse_region(name, opt_status):
    return RegionOptStatus._parse_region({'RegionName': name, 'RegionOptStatus': opt_status})[1]


class TestAWSRegionOptStatus(unittest.TestCase):

    def test_region_enabled_by_default(self):
        region = parse_region('eu-west-1', 'ENABLED_BY_DEFAULT')

        assert region['id'] == region['name'] == region['region'] == 'eu-west-1'
        assert region['enabled'] is True
        assert region['enabled_by_default'] is True
        assert region['enabled_by_opt_in'] is False

    def test_region_enabled_by_opt_in(self):
        region = parse_region('af-south-1', 'ENABLED')

        assert region['enabled'] is True
        assert region['enabled_by_default'] is False
        assert region['enabled_by_opt_in'] is True

    def test_region_being_enabled(self):
        # Resources can already exist there, so it counts as enabled
        region = parse_region('ap-east-1', 'ENABLING')

        assert region['enabled'] is True
        assert region['enabled_by_opt_in'] is True

    def test_region_disabled(self):
        region = parse_region('me-south-1', 'DISABLED')

        assert region['enabled'] is False
        assert region['enabled_by_opt_in'] is False

    def test_region_being_disabled(self):
        # The decision to close it has already been taken, so it is not reported as opted in
        region = parse_region('eu-south-2', 'DISABLING')

        assert region['enabled'] is False
        assert region['enabled_by_opt_in'] is False


if __name__ == '__main__':
    unittest.main()
