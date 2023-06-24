import pytest

from jose_aws_kms_extension.backends.kms import utils
from jose_aws_kms_extension.exceptions import KMSInvalidKeyFormatError


def test_validate_key_format__with_jwk_format_key__should_throw_exception() -> None:
    with pytest.raises(
        KMSInvalidKeyFormatError,
        match=(
            "Provided key isn't supported by KMS. "
            "Expected a string with key-id, key-id ARN, key-alias or key-alias ARN."
        )
    ):
        utils.validate_key_format({"kid": "test kid", "key": "test key"})  # type: ignore[arg-type]


def test_validate_key_format__with_invalid_key_str__should_throw_exception() -> None:
    with pytest.raises(
        KMSInvalidKeyFormatError,
        match=(
            "Provided key isn't supported by KMS. "
            "Expected a string with key-id, key-id ARN, key-alias or key-alias ARN."
        )
    ):
        utils.validate_key_format("key id with spaces")


def test_validate_key_format__with_str_format_key__should_do_nothing() -> None:
    try:
        utils.validate_key_format("valid-key-id")
    except Exception:
        pytest.fail("Exception was raised from `validate_key_format`.")
