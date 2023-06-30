import abc
from types import SimpleNamespace
from typing import Callable, Optional, Sequence

import boto3
from jose.backends.base import Key
from jose.constants import ALGORITHMS
from jose.exceptions import JWSAlgorithmError
from mypy_boto3_kms.client import KMSClient
from mypy_boto3_kms.type_defs import SignResponseTypeDef, VerifyResponseTypeDef

from jose_aws_kms_extension.backends.kms import utils

_MESSAGE_TYPE = SimpleNamespace(
    RAW='RAW',
    DIGEST='DIGEST'
)


class KMSAsymmetricSigningKey(abc.ABC, Key):
    """
    Abstract class representing an AWS KMS Asymmetric Signing Key.
    Ref: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#asymmetric-keys-concept
    """

    _key: str
    _algorithm: str
    _grant_tokens: Sequence[str]

    def __init__(
        self,
        key: str,
        algorithm: str,
        grant_tokens: Optional[Sequence[str]] = None,
    ):
        """
        :param key: AWS KMS Key ID (it can be a key ID, key ARN, key alias or key alias ARN)
        :param algorithm: Signing algorithm to be used with the key.
        :param grant_tokens: A unique, nonsecret, variable-length, base64-encoded string that represents a grant.

        :raises jose.exceptions.JWEAlgorithmUnsupportedError: If and unsupported algorithm is passes in the input.
        :raise KMSInvalidKeyFormatError: If the key format doesn't match to a KMS specific key format.
        """
        if algorithm not in ALGORITHMS.KMS_ASYMMETRIC_SIGNING:
            raise JWSAlgorithmError(
                f"{algorithm} is not part of supported KMS asymmetric algorithms: {ALGORITHMS.KMS_ASYMMETRIC_SIGNING}"
            )
        utils.validate_key_format(key)

        super().__init__(key=key, algorithm=algorithm)
        self._key = key
        self._algorithm = algorithm
        self._grant_tokens = grant_tokens or []


class BotoKMSAsymmetricSigningKey(KMSAsymmetricSigningKey):
    """
    Class representing an AWS KMS Asymmetric key, that uses Boto KMS Client for signing.
    """

    _kms_client: KMSClient

    def __init__(
        self,
        key: str,
        algorithm: str,
        grant_tokens: Optional[Sequence[str]] = None,
        kms_client: Optional[KMSClient] = None,
    ):
        """
        See :func:`~jose_aws_kms_extension.backends.kms.KmsAsymmetricSigningKey.__init__`.

        :param kms_client: Boto KMS client to be used for all operations with the key.
        """

        super().__init__(key, algorithm, grant_tokens)

        self._kms_client = kms_client or boto3.client("kms")

    def sign(self, msg: bytes) -> bytes:
        """
        See :func:`~jose.backends.base.Key.sign`.

        :raises jose_aws_kms_extension.exceptions.KMSValidationError: If validation exception is thrown from KMS.
        :raises jose_aws_kms_extension.exceptions.KMSTransientError: If transient exception is thrown from KMS.
        """

        message = self._get_message(msg)
        with utils.default_kms_exception_handing(self._kms_client):
            res: SignResponseTypeDef = self._kms_client.sign(
                KeyId=self._key,
                Message=message,
                MessageType=_MESSAGE_TYPE.DIGEST,
                SigningAlgorithm=self._algorithm,  # type: ignore[arg-type]
                GrantTokens=self._grant_tokens,
            )
            return res["Signature"]

    def verify(self, msg: bytes, sig: bytes) -> bool:
        """
        See :func:`~jose.backends.base.Key.verify`.

        :raises jose_aws_kms_extension.exceptions.KMSValidationError: If validation exception is thrown from KMS.
        :raises jose_aws_kms_extension.exceptions.KMSTransientError: If transient exception is thrown from KMS.
        """

        message = self._get_message(msg)
        with utils.default_kms_exception_handing(self._kms_client):
            try:
                verify_result: VerifyResponseTypeDef = self._kms_client.verify(
                    KeyId=self._key,
                    Message=message,
                    MessageType=_MESSAGE_TYPE.DIGEST,
                    Signature=sig,
                    SigningAlgorithm=self._algorithm,  # type: ignore[arg-type]
                )
            except self._kms_client.exceptions.KMSInvalidSignatureException:
                return False
            else:
                return verify_result["SignatureValid"]

    def _get_message(self, msg: bytes) -> bytes:
        try:
            # TODO: Make this call in __init__, when setting the algorithm.
            message_digest_provider: Callable = ALGORITHMS.HASHES[self._algorithm]
        except KeyError:
            raise JWSAlgorithmError(f"Provided algorithm: {self._algorithm}, doesn't support message digesting.")
        return message_digest_provider(msg).digest()
