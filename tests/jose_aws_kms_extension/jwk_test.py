from unittest import mock

from jose.backends import DIRKey
from jose.constants import ALGORITHMS
from jose.jwk import get_key

from jose_aws_kms_extension.backends.kms.symmetric.encryption import BotoKmsSymmetricEncryptionKey


def test_get_key__with_symmetric_default_algorithm__should_return_boto_symmetric_encryption_key() -> None:
    key_class = get_key(ALGORITHMS.SYMMETRIC_DEFAULT)

    assert key_class is BotoKmsSymmetricEncryptionKey


@mock.patch('jose_aws_kms_extension.jwk.jose_jwk_get_key')
def test_get_key__with_another_algorithm__should_call_jose_jwk_get_key(mock_jose_jwk_get_key: mock.MagicMock) -> None:
    mock_jose_jwk_get_key.return_value = mock.MagicMock(spec=DIRKey)

    key_class = get_key(ALGORITHMS.DIR)

    assert key_class is mock_jose_jwk_get_key.return_value
