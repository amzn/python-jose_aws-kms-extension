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

    KMS_ASYMMETRIC_SIGNING: Set[str] = {
        RSASSA_PKCS1_V1_5_SHA_256,
        RSASSA_PKCS1_V1_5_SHA_384,
        RSASSA_PKCS1_V1_5_SHA_512,
        RSASSA_PSS_SHA_256,
        RSASSA_PSS_SHA_384,
        RSASSA_PSS_SHA_512,
    }

    HASHES: Dict[str, Callable] = {
        RSASSA_PKCS1_V1_5_SHA_256: hashlib.sha256,
        RSASSA_PKCS1_V1_5_SHA_384: hashlib.sha384,
        RSASSA_PKCS1_V1_5_SHA_512: hashlib.sha512,
        RSASSA_PSS_SHA_256: hashlib.sha256,
        RSASSA_PSS_SHA_384: hashlib.sha384,
        RSASSA_PSS_SHA_512: hashlib.sha512,
    }

    # AWS KMS CEK Encryption algorithms
    SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT"
    KMS_SYMMETRIC_ENCRYPTION = {SYMMETRIC_DEFAULT}

    HASHES.update(jose_constants.Algorithms.HASHES)
    SUPPORTED = jose_constants.Algorithms.SUPPORTED.union(KMS_ASYMMETRIC_SIGNING).union(KMS_SYMMETRIC_ENCRYPTION)
    ALL = jose_constants.Algorithms.ALL.union(KMS_ASYMMETRIC_SIGNING).union(KMS_SYMMETRIC_ENCRYPTION)


# Monkey patching jose.constants.ALGORITHMS
jose_constants.ALGORITHMS = Algorithms()
