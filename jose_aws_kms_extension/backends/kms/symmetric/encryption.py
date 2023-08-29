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
from types import SimpleNamespace
from typing import Tuple, Mapping, Optional, Sequence

import boto3
from jose.backends.base import Key
from jose.constants import ALGORITHMS
from jose.exceptions import JWEAlgorithmUnsupportedError
from mypy_boto3_kms.client import KMSClient
from mypy_boto3_kms.literals import DataKeySpecType

from jose_aws_kms_extension import exceptions
from jose_aws_kms_extension.backends.kms import constants as kms_be_consts
from jose_aws_kms_extension.backends.kms import utils

_DATA_KEY_SPECS = SimpleNamespace(
    AES_128='AES_128',
    AES_256='AES_256'
)
_ENCRYPTION_METHOD_TO_KEY_SPEC_DICT = {
    ALGORITHMS.A128GCM: _DATA_KEY_SPECS.AES_128,
    ALGORITHMS.A128CBC: _DATA_KEY_SPECS.AES_128,
    ALGORITHMS.A128CBC_HS256: _DATA_KEY_SPECS.AES_128,
    ALGORITHMS.A256GCM: _DATA_KEY_SPECS.AES_256,
    ALGORITHMS.A256CBC: _DATA_KEY_SPECS.AES_256,
    ALGORITHMS.A256CBC_HS512: _DATA_KEY_SPECS.AES_256,
}


class KMSSymmetricEncryptionKey(abc.ABC, Key):
    """
    Abstract class representing AWS KMS Symmetric Key.
    Ref: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#symmetric-cmks
    """
    _key: str
    _algorithm: str
    _encryption_context: Mapping[str, str]
    _grant_tokens: Sequence[str]

    def __init__(
        self,
        key: str,
        algorithm: str = ALGORITHMS.SYMMETRIC_DEFAULT,
        encryption_context: Optional[Mapping[str, str]] = None,
        grant_tokens: Optional[Sequence[str]] = None,
    ):
        """
        :param key: Encryption keys (it can be a key-id, key-id ARN, key-alias or key-alias ARN).
        :param algorithm: Encryption algorithm to be used with the key.
        :param encryption_context: A collection of non-secret key-value pairs that represent additional authenticated
            data.
        :param grant_tokens: A unique, nonsecret, variable-length, base64-encoded string that represents a grant.

        :raises jose.exceptions.JWEAlgorithmUnsupportedError: If an unsupported algorithm is passes in the input.
        :raise KMSInvalidKeyFormatError: If the key format doesn't match to a KMS specific key format.
        """
        if algorithm not in ALGORITHMS.KMS_SYMMETRIC_ENCRYPTION:
            raise JWEAlgorithmUnsupportedError(
                f"{algorithm} is not part of supported-algorithms: {ALGORITHMS.KMS_SYMMETRIC_ENCRYPTION}"
            )
        utils.validate_key_format(key)

        super().__init__(key=key, algorithm=algorithm)
        self._key = key
        self._algorithm = algorithm
        self._encryption_context = encryption_context or {}
        self._grant_tokens = grant_tokens or []

    @abc.abstractmethod
    def generate_data_key(self, enc: str,) -> Tuple[bytes, bytes]:
        """
        Method for generating data-key using the symmetric key.

        :param enc: Encryption method, for which the data-key will be used.
        :return (bytes, bytes): A tuple containing the plain-text data-key and the encrypted data-key.
        """
        ...


class BotoKMSSymmetricEncryptionKey(KMSSymmetricEncryptionKey):
    """
    Class representing an AWS KMS Symmetric key.
    It implements limited methods needed for `Key` operations. We can implement more methods, when we need them.
    """
    _kms_client: KMSClient

    def __init__(
        self,
        key: str,
        algorithm: str = ALGORITHMS.SYMMETRIC_DEFAULT,
        encryption_context: Optional[Mapping[str, str]] = None,
        grant_tokens: Optional[Sequence[str]] = None,
        kms_client: Optional[KMSClient] = None,
    ):
        """
        See :func:`~jose_aws_kms_extension.backends.kms.KmsSymmetricEncryptionKey.__init__`.

        :param kms_client: Boto KMS client to be used for all operations with the key.
        """
        super().__init__(key=key, algorithm=algorithm, encryption_context=encryption_context, grant_tokens=grant_tokens)
        self._kms_client = kms_client or boto3.client("kms")

    def generate_data_key(self, enc: str) -> Tuple[bytes, bytes]:
        """
        See :func:`~jose_aws_kms_extension.backends.kms.KmsSymmetricEncryptionKey.generate_data_key`.

        :raises jose_aws_kms_extension.exceptions.KMSValidationError: If validation exception is thrown from KMS.
        :raises jose_aws_kms_extension.exceptions.KMSTransientError: If transient exception is thrown from KMS.
        """

        key_spec = self._get_key_spec(enc)
        with utils.default_kms_exception_handing(self._kms_client):
            data_key_response = self._kms_client.generate_data_key(
                KeyId=self._key,
                KeySpec=key_spec,
                EncryptionContext=self._encryption_context,
                GrantTokens=self._grant_tokens,
            )
            return data_key_response["Plaintext"], data_key_response["CiphertextBlob"]

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        """
        See :func:`~jose.backends.base.Key.unwrap_key`.

        :raises jose_aws_kms_extension.exceptions.KMSValidationError: If validation exception is thrown from KMS.
        :raises jose_aws_kms_extension.exceptions.KMSTransientError: If transient exception is thrown from KMS.
        """
        with utils.default_kms_exception_handing(self._kms_client):
            try:
                decryption_response = self._kms_client.decrypt(
                    CiphertextBlob=wrapped_key,
                    KeyId=self._key,
                    EncryptionAlgorithm=self._algorithm,  # type: ignore[arg-type]
                    EncryptionContext=self._encryption_context,
                    GrantTokens=self._grant_tokens,
                )
            except (
                self._kms_client.exceptions.InvalidCiphertextException,
                self._kms_client.exceptions.IncorrectKeyException,
            ) as exc:
                raise exceptions.KMSValidationError(kms_be_consts.DEFAULT_KMS_VALIDATION_ERROR_MESSAGE) from exc
            else:
                return decryption_response['Plaintext']

    @staticmethod
    def _get_key_spec(enc: str) -> DataKeySpecType:
        try:
            return _ENCRYPTION_METHOD_TO_KEY_SPEC_DICT[enc]
        except KeyError as exc:
            raise JWEAlgorithmUnsupportedError(f"Unsupported encryption method {enc}") from exc
