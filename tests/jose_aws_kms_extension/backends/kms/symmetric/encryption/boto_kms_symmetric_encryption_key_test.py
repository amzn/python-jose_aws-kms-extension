import re
from typing import Mapping, Sequence
from unittest.mock import MagicMock

import pytest
from jose.constants import ALGORITHMS
from jose.exceptions import JWEAlgorithmUnsupportedError, JWEError

from jose_aws_kms_extension.backends.kms.symmetric.encryption import (
    BotoKmsSymmetricEncryptionKey, _DATA_KEY_SPECS,
)


@pytest.fixture
def valid_key() -> str:
    return 'test_key_arn'


@pytest.fixture
def valid_algorithm() -> str:
    return ALGORITHMS.SYMMETRIC_DEFAULT


@pytest.fixture
def unsupported_algorithm() -> str:
    return ALGORITHMS.RSA_OAEP_256


@pytest.fixture
def boto_kms_symmetric_encryption_key(
    valid_key: str, valid_algorithm: str, mock_kms_client: MagicMock
) -> BotoKmsSymmetricEncryptionKey:
    return BotoKmsSymmetricEncryptionKey(key=valid_key, algorithm=valid_algorithm, kms_client=mock_kms_client)


@pytest.fixture
def unsupported_enc() -> str:
    return 'Unsupported enc'


@pytest.fixture
def valid_enc() -> str:
    return ALGORITHMS.A256GCM


@pytest.fixture
def encryption_context() -> Mapping[str, str]:
    return {'context-key1': 'val1', 'context-key2': 'val2'}


@pytest.fixture
def grant_tokens() -> Sequence[str]:
    return ['token1', 'token2']


@pytest.fixture
def wrapped_key() -> bytes:
    return b'test wrapped_key'


def test_generate_data_key__with_unsupported_alg__should_throw_error(
    valid_key: str, unsupported_algorithm: str, mock_kms_client: MagicMock
) -> None:
    with pytest.raises(
        JWEAlgorithmUnsupportedError,
        match=f"{unsupported_algorithm} is not part of supported-algorithms: {ALGORITHMS.KMS_SYMMETRIC_ENCRYPTION}"
    ):
        BotoKmsSymmetricEncryptionKey(key=valid_key, algorithm=unsupported_algorithm, kms_client=mock_kms_client)


def test_generate_data_key__with_unsupported_enc__should_throw_error(
    boto_kms_symmetric_encryption_key: BotoKmsSymmetricEncryptionKey, mock_kms_client: MagicMock, unsupported_enc: str
) -> None:
    with pytest.raises(JWEAlgorithmUnsupportedError, match=f'Unsupported encryption method {unsupported_enc}'):
        boto_kms_symmetric_encryption_key.generate_data_key(enc=unsupported_enc)


def test_generate_data_key__with_error_from_kms__should_throw_error(
    boto_kms_symmetric_encryption_key: BotoKmsSymmetricEncryptionKey, mock_kms_client: MagicMock, valid_enc: str
) -> None:
    mock_kms_client.generate_data_key.side_effect = Exception("test exception")

    with pytest.raises(JWEError, match='Exception was thrown while generating data-key.') as exc_info:
        boto_kms_symmetric_encryption_key.generate_data_key(enc=valid_enc)

    assert exc_info.value.__cause__ is mock_kms_client.generate_data_key.side_effect


def test_generate_data_key__with_valid_enc__should_return_data_key(
    valid_key: str, boto_kms_symmetric_encryption_key: BotoKmsSymmetricEncryptionKey, mock_kms_client: MagicMock,
    valid_enc: str
) -> None:
    mock_kms_client.generate_data_key.return_value = {
        'Plaintext': b'plaintext_key', 'CiphertextBlob': b'encrypted_key'
    }

    plaintext_key, encrypted_key = boto_kms_symmetric_encryption_key.generate_data_key(enc=valid_enc)

    assert plaintext_key is mock_kms_client.generate_data_key.return_value['Plaintext']
    assert encrypted_key is mock_kms_client.generate_data_key.return_value['CiphertextBlob']
    mock_kms_client.generate_data_key.assert_called_with(
        KeyId=valid_key, KeySpec=_DATA_KEY_SPECS.AES_256, EncryptionContext={}, GrantTokens=[])


def test_generate_data_key__with_valid_enc_and_optional_arguments__should_return_data_key(
    valid_key: str, boto_kms_symmetric_encryption_key: BotoKmsSymmetricEncryptionKey, mock_kms_client: MagicMock,
    valid_enc: str, encryption_context: Mapping[str, str], grant_tokens: Sequence[str]
) -> None:
    mock_kms_client.generate_data_key.return_value = {
        'Plaintext': b'plaintext_key', 'CiphertextBlob': b'encrypted_key'
    }

    plaintext_key, encrypted_key = boto_kms_symmetric_encryption_key.generate_data_key(
        enc=valid_enc, encryption_context=encryption_context, grant_tokens=grant_tokens)

    assert plaintext_key is mock_kms_client.generate_data_key.return_value['Plaintext']
    assert encrypted_key is mock_kms_client.generate_data_key.return_value['CiphertextBlob']
    mock_kms_client.generate_data_key.assert_called_with(
        KeyId=valid_key, KeySpec=_DATA_KEY_SPECS.AES_256, EncryptionContext=encryption_context,
        GrantTokens=grant_tokens)


def test_unwrap_key__with_exception_from_kms__should_throw_exception(
    boto_kms_symmetric_encryption_key: BotoKmsSymmetricEncryptionKey, mock_kms_client: MagicMock, wrapped_key: bytes
) -> None:
    mock_kms_client.decrypt.side_effect = Exception("test exception")

    with pytest.raises(JWEError, match=re.escape('Exception was thrown while decryption.')) as exc_info:
        boto_kms_symmetric_encryption_key.unwrap_key(wrapped_key=wrapped_key)

    assert exc_info.value.__cause__ is mock_kms_client.decrypt.side_effect


def test_unwrap_key__with_response_from_kms__should_return_decrypted_data(
    boto_kms_symmetric_encryption_key: BotoKmsSymmetricEncryptionKey, mock_kms_client: MagicMock, wrapped_key: bytes
) -> None:
    mock_kms_client.decrypt.return_value = {"Plaintext": "test decrypted data"}

    decrypted_data = boto_kms_symmetric_encryption_key.unwrap_key(wrapped_key=wrapped_key)

    assert decrypted_data == mock_kms_client.decrypt.return_value["Plaintext"]
