import base64
import re
import zlib

from ScoutSuite.core.console import print_exception

ec2_classic = "EC2-Classic"

# Global condition keys that tie a request to a VPC endpoint, and therefore keep a resource off the
# public path even though the service endpoint itself is reachable from the Internet
VPC_ENDPOINT_CONDITION_KEYS = ['aws:sourcevpce', 'aws:sourcevpc', 'aws:vpcsourceip']


def get_caller_identity(session):
    sts_client = session.client("sts")
    identity = sts_client.get_caller_identity()
    return identity


def get_aws_account_id(session):
    caller_identity = get_caller_identity(session)
    account_id = caller_identity["Arn"].split(":")[4]
    return account_id


def get_partition_name(session):
    caller_identity = get_caller_identity(session)
    partition_name = caller_identity["Arn"].split(":")[1]
    return partition_name


def is_throttled(exception):
    """
    Determines whether the exception is due to API throttling.

    :param exception:                           Exception raised
    :return:                            True if it's a throttling exception else False
    """
    # taken from botocore.retries.standard.ThrottledRetryableChecker
    throttled_errors = [
        'Throttling',
        'ThrottlingException',
        'ThrottledException',
        'RequestThrottledException',
        'TooManyRequestsException',
        'ProvisionedThroughputExceededException',
        'TransactionInProgressException',
        'RequestLimitExceeded',
        'BandwidthLimitExceeded',
        'LimitExceededException',
        'RequestThrottled',
        'SlowDown',
        'PriorRequestNotComplete',
        'EC2ThrottledException',
    ]

    try:
        throttled = (hasattr(exception, "response")
                     and exception.response
                     and "Error" in exception.response
                     and exception.response["Error"]["Code"] in throttled_errors) \
                    or \
                    any(error in str(exception) for error in throttled_errors)
        return throttled
    except Exception as e:
        print_exception(f'Unable to validate exception {exception} for AWS throttling: {e}')
        return False


def get_keys(src, dst, keys):
    """
    Copies the value of keys from source object to dest object

    :param src:                         Source object
    :param dst:                         Destination object
    :param keys:                        Keys
    :return:
    """
    for key in keys:
        dst[key] = src[key] if key in src else None


def get_name(src, dst, default_attribute):
    """

    :param src:                         Source object
    :param dst:                         Destination object
    :param default_attribute:           Default attribute

    :return:
    """
    name_found = False
    if "Tags" in src:
        for tag in src["Tags"]:
            if tag["Key"] == "Name" and tag["Value"] != "":
                dst["name"] = tag["Value"]
                name_found = True
    if not name_found:
        dst["name"] = src[default_attribute]
    return dst["name"]


def no_camel(name):
    """
    Converts CamelCase to camel_case

    :param name:                        Name string to convert
    :return:
    """
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def snake_keys(d):
    """
    Converts a dictionary with CamelCase keys to camel_case

    :param name:                        d Dictionary to iterate over
    :return:
    """

    new_table = {}
    if isinstance(d, dict):
        for k in d.keys():
            new_key = no_camel(k)
            if isinstance(d[k], dict):
                new_table[new_key] = snake_keys(d[k])
            elif isinstance(d[k], list):
                new_ary = []
                for v in d[k]:
                    if isinstance(v, dict):
                        new_ary.append(snake_keys(v))
                    else:
                        new_ary.append(v)
                new_table[new_key] = new_ary
            else:
                new_table[new_key] = d[k]
    return new_table


def policy_restricts_to_vpc_endpoint(policy):
    """
    Whether a resource-based policy confines access to a VPC endpoint, either by denying anything
    coming from elsewhere or by only allowing what comes through the endpoint.

    :param policy:                      Resource-based policy document, as a dictionary
    :return:                            True when the policy closes the public path
    """

    for statement in policy.get('Statement', []):
        condition = statement.get('Condition', {})
        if not isinstance(condition, dict):
            continue
        for operator, condition_keys in condition.items():
            if not isinstance(condition_keys, dict):
                continue
            for condition_key in condition_keys:
                if condition_key.lower() in VPC_ENDPOINT_CONDITION_KEYS:
                    # A Deny on requests not coming from the endpoint and an Allow limited to the
                    # endpoint both close the public path, the negated operators distinguish them
                    negated = 'Not' in operator
                    if (statement.get('Effect') == 'Deny') == negated:
                        return True
    return False


def format_arn(partition, service, region, account_id, resource_id, resource_type=None):
    """
    Formats a resource ARN based on the parameters

    :param partition:                   The partition where the resource is located
    :param service:                     The service namespace that identified the AWS product
    :param region:                      The corresponding region
    :param account_id:                  The ID of the AWS account that owns the resource
    :param resource_id:                 The resource identified
    :param resource_type:               (Optional) The resource type
    :return:                            Resource ARN
    """

    try:
        # If a resource type is specified
        if resource_type is not None:
            arn = f"arn:{partition}:{service}:{region}:{account_id}:{resource_type}/{resource_id}"
        else:
            arn = f"arn:{partition}:{service}:{region}:{account_id}:{resource_id}"
    except Exception as e:
        print_exception(f'Failed to parse a resource ARN: {e}')
        return None
    return arn


def decode_user_data(user_data):
    """
    Decodes the user data of an EC2 instance, a launch template version or a launch configuration.

    The API hands it over base64 encoded, and the tooling that wrote it may itself have encoded or
    gzipped the payload beforehand, which is why several layers are peeled off here.

    :param user_data:                   Base64 encoded user data
    :return:                            User data as a string
    """

    try:
        value = base64.b64decode(user_data)
    except base64.binascii.Error:
        value = base64.b64decode(f'{user_data}===')
    if value[0:2] == b'\x1f\x8b':  # GZIP magic number
        return zlib.decompress(value, zlib.MAX_WBITS | 32).decode('utf-8')
    else:
        # Try another run of b64 decoding
        try:
            value = base64.b64decode(value)
        except Exception:
            pass
        # Return a string, not a byte string
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            return value.decode('latin-1')


def identify_user_data_secrets(user_data):
    """
    Parses user data in order to identify secrets and credentials.

    :param user_data:                   User data as a string
    :return:                            Dictionary of the secrets found, empty when there are none
    """

    secrets = {}

    if user_data:
        aws_access_key_regex = re.compile(r'(?:^|[^0-9A-Z])(AKIA[0-9A-Z]{16})(?:[^0-9A-Z]|$)')
        aws_secret_access_key_regex = re.compile(r'(?:^|[^0-9a-zA-Z/+])([0-9a-zA-Z/+]{40})(?:[^0-9a-zA-Z/+]|$)')
        rsa_private_key_regex = re.compile('(?s)(-----BEGIN RSA PRIVATE KEY-----.+?-----END .+?-----)')
        keywords = ['password', 'secret', 'aws_access_key_id', 'aws_secret_access_key', 'aws_session_token']

        aws_access_key_list = aws_access_key_regex.findall(user_data)
        if aws_access_key_list:
            secrets['AWS Access Key IDs'] = aws_access_key_list
        aws_secret_access_key_list = aws_secret_access_key_regex.findall(user_data)
        if aws_secret_access_key_list:
            secrets['AWS Secret Access Keys'] = aws_secret_access_key_list
        rsa_private_key_list = rsa_private_key_regex.findall(user_data)
        if rsa_private_key_list:
            secrets['Private Keys'] = rsa_private_key_list
        word_list = []
        for word in keywords:
            if word in user_data.lower():
                word_list.append(word)
        if word_list:
            secrets['Flagged Words'] = word_list

    return secrets
