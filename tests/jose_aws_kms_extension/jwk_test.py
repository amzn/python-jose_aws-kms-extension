from typing import Set
from unittest import mock

import pytest
from jose.backends import DIRKey
from jose.backends.base import Key
from jose.constants import ALGORITHMS
from jose.jwk import get_key, construct

from jose_aws_kms_extension.backends.kms.asymmetric.signing import BotoKmsAsymmetricSigningKey
from jose_aws_kms_extension.backends.kms.symmetric.encryption import BotoKmsSymmetricEncryptionKey


@pytest.fixture
def valid_asymmetric_signing_algorithms() -> Set[str]:
    return ALGORITHMS.KMS_ASYMMETRIC_SIGNING


def test_get_key__with_symmetric_default_algorithm__should_return_boto_symmetric_encryption_key() -> None:
    key_class = get_key(ALGORITHMS.SYMMETRIC_DEFAULT)

    assert key_class is BotoKmsSymmetricEncryptionKey


def test_get_key__with_kms_asymmetric_signing_algorithm__should_return_boto_asymmetric_signing_key(
    valid_asymmetric_signing_algorithms: Set[str]
) -> None:
    for algorithm in valid_asymmetric_signing_algorithms:
        key_class = get_key(algorithm)
        assert key_class is BotoKmsAsymmetricSigningKey


@mock.patch('jose_aws_kms_extension.jwk.jose_jwk_get_key')
def test_get_key__with_another_algorithm__should_call_jose_jwk_get_key(mock_jose_jwk_get_key: mock.MagicMock) -> None:
    mock_jose_jwk_get_key.return_value = mock.MagicMock(spec=DIRKey)

    key_class = get_key(ALGORITHMS.DIR)

    assert key_class is mock_jose_jwk_get_key.return_value


def test_construct__with_key_object__should_return_same_object() -> None:
    input_key = mock.MagicMock(spec=Key)

    output_key = construct(key_data=input_key)

    assert output_key is input_key


@mock.patch('jose_aws_kms_extension.jwk.jose_jwk_construct')
def test_construct__with_non_key_object_key__should_call_jose_jwk_construct(
    mock_jose_jwk_construct: mock.MagicMock
) -> None:
    mock_jose_jwk_construct.return_value = mock.MagicMock(spec=Key)
    input_key = mock.MagicMock()
    input_algorithm = mock.MagicMock()

    output_key = construct(key_data=input_key, algorithm=input_algorithm)

    mock_jose_jwk_construct.assert_called_once_with(key_data=input_key, algorithm=input_algorithm)
    assert output_key is mock_jose_jwk_construct.return_value
