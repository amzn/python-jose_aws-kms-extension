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

import abc
import hashlib
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
    _hash_provider: Callable[[bytes], 'hashlib._Hash']
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

        :raises jose.exceptions.JWSAlgorithmError: If an unsupported algorithm is passes in the input.
        :raise KMSInvalidKeyFormatError: If the key format doesn't match to a KMS specific key format.
        """
        if algorithm not in ALGORITHMS.KMS_ASYMMETRIC_SIGNING:
            raise JWSAlgorithmError(
                f"{algorithm} is not part of supported KMS asymmetric algorithms: {ALGORITHMS.KMS_ASYMMETRIC_SIGNING}"
            )
        utils.validate_key_format(key)
        self._hash_provider = self._get_hash_provider(algorithm)

        super().__init__(key=key, algorithm=algorithm)
        self._key = key
        self._algorithm = algorithm
        self._grant_tokens = grant_tokens or []

    @staticmethod
    def _get_hash_provider(signing_algorithm: str) -> Callable[[bytes], 'hashlib._Hash']:
        """
        This method returns a callable message hash-provider for the given signing-algorithm.
        """
        try:
            return ALGORITHMS.HASHES[signing_algorithm]
        except KeyError as exc:
            raise JWSAlgorithmError(
                f"Unable to find a hashing algorithm for the provided signing algorithm: {signing_algorithm}."
            ) from exc


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

        with utils.default_kms_exception_handing(self._kms_client):
            res: SignResponseTypeDef = self._kms_client.sign(
                KeyId=self._key,
                Message=self._hash_provider(msg).digest(),
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

        with utils.default_kms_exception_handing(self._kms_client):
            try:
                verify_result: VerifyResponseTypeDef = self._kms_client.verify(
                    KeyId=self._key,
                    Message=self._hash_provider(msg).digest(),
                    MessageType=_MESSAGE_TYPE.DIGEST,
                    Signature=sig,
                    SigningAlgorithm=self._algorithm,  # type: ignore[arg-type]
                )
            except self._kms_client.exceptions.KMSInvalidSignatureException:
                return False
            else:
                return verify_result["SignatureValid"]
