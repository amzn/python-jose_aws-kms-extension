from typing import Dict, Type
from unittest import mock
from unittest.mock import MagicMock

import pytest
from botocore.errorfactory import BaseClientExceptions
from jose.constants import ALGORITHMS
from jose.exceptions import JWSAlgorithmError
from mypy_boto3_kms.client import BotocoreClientError

from jose_aws_kms_extension.backends.kms.asymmetric.signing import BotoKMSAsymmetricSigningKey
from jose_aws_kms_extension.exceptions import KMSError
from tests.jose_aws_kms_extension.backends.kms.conftest import PARAMETRIZED_KMS_ERROR_TEST_CONSTS


@pytest.fixture
def valid_key() -> str:
    return 'test_key_arn'


@pytest.fixture
def valid_algorithm() -> str:
    return ALGORITHMS.RSASSA_PKCS1_V1_5_SHA_256


@pytest.fixture
def unsupported_algorithm() -> str:
    return ALGORITHMS.RSA_OAEP_256


@pytest.fixture
def unsupported_key() -> dict:
    return {"test_key": "test_value"}


@pytest.fixture
def boto_kms_asymmetric_signing_key(
    valid_key: str, valid_algorithm: str, mock_kms_client: MagicMock
) -> BotoKMSAsymmetricSigningKey:
    return BotoKMSAsymmetricSigningKey(key=valid_key, algorithm=valid_algorithm, kms_client=mock_kms_client)


@pytest.fixture
def msg() -> bytes:
    return b'test signing input'


@pytest.fixture
def sig() -> bytes:
    return b'test signature'


@pytest.fixture
def kms_invalid_signature_exception(
    kms_client_exceptions: BaseClientExceptions, error_response: Dict, operation_name: str
) -> BaseClientExceptions:
    return kms_client_exceptions.KMSInvalidSignatureException(
        error_response, operation_name)  # type: ignore[misc]


def test_construct_boto_kms_asymmetric_signing_key__with_unsupported_algorithm__should_throw_error(
    valid_key: str, unsupported_algorithm: str, mock_kms_client: MagicMock
) -> None:
    with pytest.raises(
        JWSAlgorithmError,
        match=f"{unsupported_algorithm} is not part of supported KMS asymmetric algorithms: "
              f"{ALGORITHMS.KMS_ASYMMETRIC_SIGNING}"
    ):
        BotoKMSAsymmetricSigningKey(key=valid_key, algorithm=unsupported_algorithm, kms_client=mock_kms_client)


def test_construct__valid_arguments__should_call_validate_key_format(
    valid_key: str, valid_algorithm: str, mock_kms_client: MagicMock, mock_validate_key_format: MagicMock
) -> None:
    BotoKMSAsymmetricSigningKey(key=valid_key, algorithm=valid_algorithm, kms_client=mock_kms_client)

    mock_validate_key_format.assert_called_once_with(valid_key)


@mock.patch('jose_aws_kms_extension.backends.kms.asymmetric.signing.ALGORITHMS.KMS_ASYMMETRIC_SIGNING')
def test_construct__with_unsupported_hashing_algorithm__should_throw_error(
    mock_kms_asymmetric_signing: MagicMock, valid_key: str, unsupported_algorithm: str, mock_kms_client: MagicMock
) -> None:
    mock_kms_asymmetric_signing.__contains__ = lambda *args, **kwargs: True

    with pytest.raises(
        JWSAlgorithmError,
        match=f"Unable to find a hashing algorithm for the provided signing algorithm: {unsupported_algorithm}."
    ) as exc_info:
        BotoKMSAsymmetricSigningKey(key=valid_key, algorithm=unsupported_algorithm, kms_client=mock_kms_client)

    assert isinstance(exc_info.value.__cause__, KeyError)


@pytest.mark.parametrize(
    argnames=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_PARAMS,
    indirect=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_INDIRECT_PARAMS,
    argvalues=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_PARAM_VALUES,
)
def test_sign__with_exception_from_kms__should_throw_jose_kms_exception(
    kms_exception_from_class_name: BotocoreClientError,
    jose_kms_exception_class: Type[KMSError],
    jose_kms_exception_message: str,
    boto_kms_asymmetric_signing_key: BotoKMSAsymmetricSigningKey,
    mock_kms_client: MagicMock,
    msg: bytes
) -> None:
    mock_kms_client.sign.side_effect = kms_exception_from_class_name
    with pytest.raises(jose_kms_exception_class, match=jose_kms_exception_message) as exc_info:
        boto_kms_asymmetric_signing_key.sign(msg=msg)

    assert exc_info.value.__cause__ is mock_kms_client.sign.side_effect


def test_sign__with_response_from_kms__should_return_signature(
    boto_kms_asymmetric_signing_key: BotoKMSAsymmetricSigningKey, mock_kms_client: MagicMock,
    msg: bytes
) -> None:
    mock_kms_client.sign.return_value = \
        {"KeyId": "Test Key", "Signature": b'Test Signature', "SigningAlgorithm": "Test Algorithm"}

    signature = boto_kms_asymmetric_signing_key.sign(msg)

    assert signature is mock_kms_client.sign.return_value["Signature"]


@pytest.mark.parametrize(
    argnames=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_PARAMS,
    indirect=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_INDIRECT_PARAMS,
    argvalues=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_PARAM_VALUES,
)
def test_verify__with_exception_from_kms__should_throw_jose_kms_exception(
    kms_exception_from_class_name: BotocoreClientError,
    jose_kms_exception_class: Type[KMSError],
    jose_kms_exception_message: str,
    boto_kms_asymmetric_signing_key: BotoKMSAsymmetricSigningKey,
    mock_kms_client: MagicMock,
    msg: bytes,
    sig: bytes,
) -> None:
    mock_kms_client.verify.side_effect = kms_exception_from_class_name
    with pytest.raises(jose_kms_exception_class, match=jose_kms_exception_message) as exc_info:
        boto_kms_asymmetric_signing_key.verify(msg, sig)

    assert exc_info.value.__cause__ is mock_kms_client.verify.side_effect


def test_verify__with_invalid_signature_exception_from_kms__should_return_invalid_signature_boolean(
    boto_kms_asymmetric_signing_key: BotoKMSAsymmetricSigningKey, mock_kms_client: MagicMock,
    msg: bytes, sig: bytes, kms_invalid_signature_exception: BaseClientExceptions
) -> None:
    mock_kms_client.verify.side_effect = kms_invalid_signature_exception
    result = boto_kms_asymmetric_signing_key.verify(msg, sig)

    assert result is False


def test_verify__with_response_from_kms__should_return_valid_signature_boolean(
    boto_kms_asymmetric_signing_key: BotoKMSAsymmetricSigningKey, mock_kms_client: MagicMock,
    msg: bytes, sig: bytes
) -> None:
    mock_kms_client.verify.return_value = \
        {"KeyId": "Test Key", "SignatureValid": True, "SigningAlgorithm": "Test Algorithm"}

    result = boto_kms_asymmetric_signing_key.verify(msg, sig)

    assert result is mock_kms_client.verify.return_value["SignatureValid"]
