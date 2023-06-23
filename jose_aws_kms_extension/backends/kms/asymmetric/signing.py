import abc
from types import SimpleNamespace
from typing import Callable, Optional

import boto3
from jose.backends.base import Key
from jose.constants import ALGORITHMS
from jose.exceptions import JWSAlgorithmError, JWSError
from mypy_boto3_kms.client import KMSClient
from mypy_boto3_kms.type_defs import SignResponseTypeDef, VerifyResponseTypeDef

_MESSAGE_TYPE = SimpleNamespace(
    RAW='RAW',
    DIGEST='DIGEST'
)


class KmsAsymmetricSigningKey(abc.ABC, Key):
    """
    Abstract class representing an AWS KMS Asymmetric Signing Key.
    Ref: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#asymmetric-keys-concept
    """

    _key: str
    _algorithm: str

    def __init__(self, key: str, algorithm: str = ALGORITHMS.RSASSA_PSS_SHA_256):
        """
        :param key: AWS KMS Key ID (it can be a key ID, key ARN, key alias or key alias ARN)
        :param algorithm: Signing algorithm to be used with the key.
        """
        if algorithm not in ALGORITHMS.KMS_ASYMMETRIC_SIGNING:
            raise JWSAlgorithmError(
                f"{algorithm} is not part of supported KMS asymmetric algorithms: {ALGORITHMS.KMS_ASYMMETRIC_SIGNING}"
            )

        if not isinstance(key, str):
            raise JWSError(f"Expected a Key ID. Key provided: {key}, isn't supported by KMS.")

        super().__init__(key=key, algorithm=algorithm)
        self._key = key
        self._algorithm = algorithm


class BotoKmsAsymmetricSigningKey(KmsAsymmetricSigningKey):
    """
    Class representing an AWS KMS Asymmetric key, that uses Boto KMS Client for signing.
    """

    _kms_client: KMSClient

    def __init__(self, key: str, algorithm: str, kms_client: Optional[KMSClient] = None):
        """
        See :func:`~jose_aws_kms_extension.backends.kms.KmsAsymmetricSigningKey.__init__`.
        :param kms_client: Boto KMS client to be used for all operations with the key.
        """

        super().__init__(key, algorithm)

        # TODO: Take a factory input to allow clients have custom configurations.
        self._kms_client = kms_client or boto3.client("kms")

    def sign(self, msg: bytes) -> bytes:
        """
        See :func:`~jose.backends.base.Key.sign`.
        """

        message = self._get_message(msg)
        try:
            res: SignResponseTypeDef = self._kms_client.sign(
                KeyId=self._key,
                Message=message,
                MessageType=_MESSAGE_TYPE.DIGEST,
                SigningAlgorithm=self._algorithm,  # type: ignore[arg-type]
            )
        except Exception as exc:
            # TODO: Have granular level of exception handling to put more meaningful context.
            raise JWSError("An exception was thrown from KMS.") from exc

        return res["Signature"]

    def verify(self, msg: bytes, sig: bytes) -> bool:
        """
        See :func:`~jose.backends.base.Key.verify`.
        """

        message = self._get_message(msg)
        try:
            verify_result: VerifyResponseTypeDef = self._kms_client.verify(
                KeyId=self._key,
                Message=message,
                MessageType=_MESSAGE_TYPE.DIGEST,
                Signature=sig,
                SigningAlgorithm=self._algorithm,  # type: ignore[arg-type]
            )
        except Exception as exc:
            # TODO: Have granular level of exception handling to put more meaningful context.
            raise JWSError("An exception was thrown from KMS.") from exc
        return verify_result["SignatureValid"]

    def _get_message(self, msg: bytes) -> bytes:
        try:
            message_digest_provider: Callable = ALGORITHMS.HASHES[self._algorithm]
        except KeyError:
            raise JWSError(f"Provided algorithm: {self._algorithm}, doesn't support message digesting.")
        return message_digest_provider(msg).digest()
