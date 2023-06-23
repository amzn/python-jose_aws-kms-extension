from unittest.mock import MagicMock

import pytest
from jose.constants import ALGORITHMS
from jose.exceptions import JWSAlgorithmError, JWSError

from jose_aws_kms_extension.backends.kms.asymmetric.signing import BotoKmsAsymmetricSigningKey


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
) -> BotoKmsAsymmetricSigningKey:
    return BotoKmsAsymmetricSigningKey(key=valid_key, algorithm=valid_algorithm, kms_client=mock_kms_client)


@pytest.fixture
def msg() -> bytes:
    return b'test signing input'


@pytest.fixture
def sig() -> bytes:
    return b'test signature'


def test_construct_boto_kms_asymmetric_signing_key__with_unsupported_key__should_throw_error(
    unsupported_key: dict, valid_algorithm: str, mock_kms_client: MagicMock
) -> None:
    with pytest.raises(
        JWSError,
        match=f"Expected a Key ID. Key provided: {unsupported_key}, isn't supported by KMS."
    ):
        BotoKmsAsymmetricSigningKey(key=unsupported_key,  # type: ignore[arg-type]
                                    algorithm=valid_algorithm, kms_client=mock_kms_client)


def test_construct_boto_kms_asymmetric_signing_key__with_unsupported_algorithm__should_throw_error(
    valid_key: str, unsupported_algorithm: str, mock_kms_client: MagicMock
) -> None:
    with pytest.raises(
        JWSAlgorithmError,
        match=f"{unsupported_algorithm} is not part of supported KMS asymmetric algorithms: "
              f"{ALGORITHMS.KMS_ASYMMETRIC_SIGNING}"
    ):
        BotoKmsAsymmetricSigningKey(key=valid_key, algorithm=unsupported_algorithm, kms_client=mock_kms_client)


def test_sign__with_unsupported_hashing_algorithm__should_throw_error(
    boto_kms_asymmetric_signing_key: BotoKmsAsymmetricSigningKey,
    msg: bytes
) -> None:
    boto_kms_asymmetric_signing_key.__setattr__("_algorithm", unsupported_algorithm)
    with pytest.raises(
        JWSError,
        match=f"Provided algorithm: {unsupported_algorithm}, doesn't support message digesting."
    ):
        boto_kms_asymmetric_signing_key.sign(msg)


def test_sign__with_error_from_kms__should_throw_error(
    boto_kms_asymmetric_signing_key: BotoKmsAsymmetricSigningKey, mock_kms_client: MagicMock,
    msg: bytes
) -> None:
    mock_kms_client.sign.side_effect = Exception("test exception")
    with pytest.raises(JWSError, match="An exception was thrown from KMS.") as exc_info:
        boto_kms_asymmetric_signing_key.sign(msg)

    assert exc_info.value.__cause__ is mock_kms_client.sign.side_effect


def test_sign__with_response_from_kms__should_return_signature(
    boto_kms_asymmetric_signing_key: BotoKmsAsymmetricSigningKey, mock_kms_client: MagicMock,
    msg: bytes
) -> None:
    mock_kms_client.sign.return_value = \
        {"KeyId": "Test Key", "Signature": b'Test Signature', "SigningAlgorithm": "Test Algorithm"}

    signature = boto_kms_asymmetric_signing_key.sign(msg)

    assert signature is mock_kms_client.sign.return_value["Signature"]


def test_verify__with_unsupported_hashing_algorithm__should_throw_error(
    boto_kms_asymmetric_signing_key: BotoKmsAsymmetricSigningKey,
    msg: bytes, sig: bytes
) -> None:
    boto_kms_asymmetric_signing_key.__setattr__("_algorithm", unsupported_algorithm)
    with pytest.raises(
        JWSError,
        match=f"Provided algorithm: {unsupported_algorithm}, doesn't support message digesting."
    ):
        boto_kms_asymmetric_signing_key.verify(msg, sig)


def test_verify__with_error_from_kms__should_throw_error(
    boto_kms_asymmetric_signing_key: BotoKmsAsymmetricSigningKey, mock_kms_client: MagicMock,
    msg: bytes, sig: bytes
) -> None:
    mock_kms_client.verify.side_effect = Exception("test exception")
    with pytest.raises(JWSError, match="An exception was thrown from KMS.") as exc_info:
        boto_kms_asymmetric_signing_key.verify(msg, sig)

    assert exc_info.value.__cause__ is mock_kms_client.verify.side_effect


def test_verify__with_response_from_kms__should_return_signature(
    boto_kms_asymmetric_signing_key: BotoKmsAsymmetricSigningKey, mock_kms_client: MagicMock,
    msg: bytes, sig: bytes
) -> None:
    mock_kms_client.verify.return_value = \
        {"KeyId": "Test Key", "SignatureValid": True, "SigningAlgorithm": "Test Algorithm"}

    result = boto_kms_asymmetric_signing_key.verify(msg, sig)

    assert result is mock_kms_client.verify.return_value["SignatureValid"]
