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

import hashlib
from typing import Callable, Dict, Set

from jose import constants as jose_constants


class Algorithms(jose_constants.Algorithms):
    """
    Extended Algorithm class to add AWS KMS supported algorithms.
    """

    # AWS KMS signature algorithms
    RSASSA_PKCS1_V1_5_SHA_256: str = "RSASSA_PKCS1_V1_5_SHA_256"
    RSASSA_PKCS1_V1_5_SHA_384: str = "RSASSA_PKCS1_V1_5_SHA_384"
    RSASSA_PKCS1_V1_5_SHA_512: str = "RSASSA_PKCS1_V1_5_SHA_512"
    RSASSA_PSS_SHA_256: str = "RSASSA_PSS_SHA_256"
    RSASSA_PSS_SHA_384: str = "RSASSA_PSS_SHA_384"
    RSASSA_PSS_SHA_512: str = "RSASSA_PSS_SHA_512"
    ECDSA_SHA_256: str = "ECDSA_SHA_256"
    ECDSA_SHA_384: str = "ECDSA_SHA_384"
    ECDSA_SHA_512: str = "ECDSA_SHA_512"

    KMS_ASYMMETRIC_SIGNING: Set[str] = {
        RSASSA_PKCS1_V1_5_SHA_256,
        RSASSA_PKCS1_V1_5_SHA_384,
        RSASSA_PKCS1_V1_5_SHA_512,
        RSASSA_PSS_SHA_256,
        RSASSA_PSS_SHA_384,
        RSASSA_PSS_SHA_512,
        ECDSA_SHA_256,
        ECDSA_SHA_384,
        ECDSA_SHA_512
    }

    HASHES: Dict[str, Callable[[bytes], 'hashlib._Hash']] = {
        **jose_constants.Algorithms.HASHES,
        RSASSA_PKCS1_V1_5_SHA_256: hashlib.sha256,
        RSASSA_PKCS1_V1_5_SHA_384: hashlib.sha384,
        RSASSA_PKCS1_V1_5_SHA_512: hashlib.sha512,
        RSASSA_PSS_SHA_256: hashlib.sha256,
        RSASSA_PSS_SHA_384: hashlib.sha384,
        RSASSA_PSS_SHA_512: hashlib.sha512,
        ECDSA_SHA_256: hashlib.sha256,
        ECDSA_SHA_384: hashlib.sha384,
        ECDSA_SHA_512: hashlib.sha512
    }

    # AWS KMS CEK Encryption algorithms
    SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT"
    KMS_SYMMETRIC_ENCRYPTION = {SYMMETRIC_DEFAULT}

    # AWS KMS Cryptographic algorithms
    KMS_CRYPTOGRAPHIC_ALGORITHMS = KMS_ASYMMETRIC_SIGNING.union(KMS_SYMMETRIC_ENCRYPTION)

    SUPPORTED = jose_constants.Algorithms.SUPPORTED.union(KMS_CRYPTOGRAPHIC_ALGORITHMS)
    ALL = jose_constants.Algorithms.ALL.union(KMS_CRYPTOGRAPHIC_ALGORITHMS)


# Monkey patching jose.constants.ALGORITHMS
jose_constants.ALGORITHMS = Algorithms()
