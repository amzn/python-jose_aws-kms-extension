import re

from jose_aws_kms_extension import exceptions


def validate_key_format(key: str) -> None:
    """
    Validates if the passed :param:`key` is in the correct format.
    :param key: AWS KMS key (it can be a key-id, key-id ARN, key-alias or key-alias ARN).
    :raise KMSInvalidKeyFormatError: If the key format doesn't match to a KMS specific key format.
    """

    if not isinstance(key, str) or not re.match(r'^\S+$', key):
        raise exceptions.KMSInvalidKeyFormatError(
            "Provided key isn't supported by KMS. "
            "Expected a string with key-id, key-id ARN, key-alias or key-alias ARN."
        )
