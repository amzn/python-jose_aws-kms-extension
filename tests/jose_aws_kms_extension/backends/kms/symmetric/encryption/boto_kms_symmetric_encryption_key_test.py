# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Mapping, Sequence, Dict, Type
from unittest import mock

import pytest
from botocore.errorfactory import BaseClientExceptions
from jose.constants import ALGORITHMS
from jose.exceptions import JWEAlgorithmUnsupportedError
from mypy_boto3_kms.client import BotocoreClientError

from jose_aws_kms_extension import exceptions as excs
from jose_aws_kms_extension.backends.kms import constants as kms_be_consts
from jose_aws_kms_extension.backends.kms.symmetric.encryption import (
    BotoKMSSymmetricEncryptionKey, _DATA_KEY_SPECS,
)
from tests.jose_aws_kms_extension.backends.kms.conftest import PARAMETRIZED_KMS_ERROR_TEST_CONSTS

pytestmark = pytest.mark.usefixtures("mock_validate_key_format")


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
    valid_key: str, valid_algorithm: str, mock_kms_client: mock.MagicMock
) -> BotoKMSSymmetricEncryptionKey:
    return BotoKMSSymmetricEncryptionKey(key=valid_key, algorithm=valid_algorithm, kms_client=mock_kms_client)


@pytest.fixture
def encryption_context() -> Mapping[str, str]:
    return {'context-key1': 'val1', 'context-key2': 'val2'}


@pytest.fixture
def grant_tokens() -> Sequence[str]:
    return ['token1', 'token2']


@pytest.fixture
def boto_kms_symmetric_encryption_key_with_optional_arguments(
    valid_key: str, valid_algorithm: str, mock_kms_client: mock.MagicMock, encryption_context: Mapping[str, str],
    grant_tokens: Sequence[str],
) -> BotoKMSSymmetricEncryptionKey:
    return BotoKMSSymmetricEncryptionKey(
        key=valid_key, algorithm=valid_algorithm, encryption_context=encryption_context, grant_tokens=grant_tokens,
        kms_client=mock_kms_client,
    )


@pytest.fixture
def unsupported_enc() -> str:
    return 'Unsupported enc'


@pytest.fixture
def valid_enc() -> str:
    return ALGORITHMS.A256GCM


@pytest.fixture
def wrapped_key() -> bytes:
    return b'test wrapped_key'


@pytest.fixture
def invalid_ciphertext_exception(
    kms_client_exceptions: BaseClientExceptions, error_response: Dict, operation_name: str
) -> BaseClientExceptions:
    return kms_client_exceptions.InvalidCiphertextException(error_response, operation_name)  # type: ignore[misc]


def test_init__with_unsupported_alg__should_throw_error(
    valid_key: str, unsupported_algorithm: str, mock_kms_client: mock.MagicMock
) -> None:
    with pytest.raises(
        JWEAlgorithmUnsupportedError,
        match=f"{unsupported_algorithm} is not part of supported-algorithms: {ALGORITHMS.KMS_SYMMETRIC_ENCRYPTION}"
    ):
        BotoKMSSymmetricEncryptionKey(key=valid_key, algorithm=unsupported_algorithm, kms_client=mock_kms_client)


def test_init__valid_arguments__should_call_validate_key_format(
    valid_key: str, valid_algorithm: str, mock_kms_client: mock.MagicMock, mock_validate_key_format: mock.MagicMock
) -> None:
    BotoKMSSymmetricEncryptionKey(key=valid_key, algorithm=valid_algorithm, kms_client=mock_kms_client)

    mock_validate_key_format.assert_called_once_with(valid_key)


def test_generate_data_key__with_unsupported_enc__should_throw_error(
    boto_kms_symmetric_encryption_key: BotoKMSSymmetricEncryptionKey, mock_kms_client: mock.MagicMock,
    unsupported_enc: str
) -> None:
    with pytest.raises(JWEAlgorithmUnsupportedError, match=f'Unsupported encryption method {unsupported_enc}'):
        boto_kms_symmetric_encryption_key.generate_data_key(enc=unsupported_enc)


@pytest.mark.parametrize(
    argnames=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_PARAMS,
    indirect=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_INDIRECT_PARAMS,
    argvalues=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_PARAM_VALUES,
)
def test_generate_data_key__with_exception_from_kms__should_throw_jose_kms_exception(
    kms_exception_from_class_name: BotocoreClientError,
    jose_kms_exception_class: Type[excs.KMSError],
    jose_kms_exception_message: str,
    boto_kms_symmetric_encryption_key: BotoKMSSymmetricEncryptionKey,
    mock_kms_client: mock.MagicMock,
    valid_enc: str,
) -> None:
    mock_kms_client.generate_data_key.side_effect = kms_exception_from_class_name
    with pytest.raises(jose_kms_exception_class, match=jose_kms_exception_message) as exc_info:
        boto_kms_symmetric_encryption_key.generate_data_key(enc=valid_enc)

    assert exc_info.value.__cause__ is mock_kms_client.generate_data_key.side_effect


def test_generate_data_key__with_valid_enc__should_return_data_key(
    valid_key: str, boto_kms_symmetric_encryption_key: BotoKMSSymmetricEncryptionKey, mock_kms_client: mock.MagicMock,
    valid_enc: str
) -> None:
    mock_kms_client.generate_data_key.return_value = {
        'Plaintext': b'plaintext_key', 'CiphertextBlob': b'encrypted_key'
    }

    plaintext_key, encrypted_key = boto_kms_symmetric_encryption_key.generate_data_key(enc=valid_enc)

    assert plaintext_key is mock_kms_client.generate_data_key.return_value['Plaintext']
    assert encrypted_key is mock_kms_client.generate_data_key.return_value['CiphertextBlob']
    mock_kms_client.generate_data_key.assert_called_once_with(
        KeyId=valid_key, KeySpec=_DATA_KEY_SPECS.AES_256, EncryptionContext={}, GrantTokens=[])


def test_generate_data_key__with_valid_enc_and_optional_kms_arguments__should_return_data_key(
    valid_key: str, boto_kms_symmetric_encryption_key_with_optional_arguments: BotoKMSSymmetricEncryptionKey,
    mock_kms_client: mock.MagicMock, valid_enc: str, encryption_context: Mapping[str, str], grant_tokens: Sequence[str]
) -> None:

    mock_kms_client.generate_data_key.return_value = {
        'Plaintext': b'plaintext_key', 'CiphertextBlob': b'encrypted_key'
    }

    plaintext_key, encrypted_key = boto_kms_symmetric_encryption_key_with_optional_arguments.generate_data_key(
        enc=valid_enc
    )

    assert plaintext_key is mock_kms_client.generate_data_key.return_value['Plaintext']
    assert encrypted_key is mock_kms_client.generate_data_key.return_value['CiphertextBlob']
    mock_kms_client.generate_data_key.assert_called_once_with(
        KeyId=valid_key, KeySpec=_DATA_KEY_SPECS.AES_256, EncryptionContext=encryption_context,
        GrantTokens=grant_tokens)


@pytest.mark.parametrize(
    argnames=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_PARAMS,
    indirect=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_INDIRECT_PARAMS,
    argvalues=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_PARAM_VALUES + [
        ('InvalidCiphertextException', excs.KMSValidationError, kms_be_consts.DEFAULT_KMS_VALIDATION_ERROR_MESSAGE),
        ('IncorrectKeyException', excs.KMSValidationError, kms_be_consts.DEFAULT_KMS_VALIDATION_ERROR_MESSAGE),
    ],
)
def test_unwrap_key__with_exception_from_kms__should_throw_jose_kms_exception(
    kms_exception_from_class_name: BotocoreClientError,
    jose_kms_exception_class: Type[excs.KMSError],
    jose_kms_exception_message: str,
    boto_kms_symmetric_encryption_key: BotoKMSSymmetricEncryptionKey,
    mock_kms_client: mock.MagicMock,
    wrapped_key: bytes,
) -> None:
    mock_kms_client.decrypt.side_effect = kms_exception_from_class_name
    with pytest.raises(jose_kms_exception_class, match=jose_kms_exception_message) as exc_info:
        boto_kms_symmetric_encryption_key.unwrap_key(wrapped_key=wrapped_key)

    assert exc_info.value.__cause__ is mock_kms_client.decrypt.side_effect


def test_unwrap_key__with_response_from_kms__should_return_decrypted_data(
    boto_kms_symmetric_encryption_key: BotoKMSSymmetricEncryptionKey, mock_kms_client: mock.MagicMock,
    wrapped_key: bytes
) -> None:
    mock_kms_client.decrypt.return_value = {"Plaintext": "test decrypted data"}

    decrypted_data = boto_kms_symmetric_encryption_key.unwrap_key(wrapped_key=wrapped_key)

    assert decrypted_data == mock_kms_client.decrypt.return_value["Plaintext"]
