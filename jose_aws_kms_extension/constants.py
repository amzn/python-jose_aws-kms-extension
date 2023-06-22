import hashlib
from typing import Callable, Dict, Set

from jose import constants as jose_constants


class Algorithms(jose_constants.Algorithms):
    # Digital signature algorithms
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

    HASHES.update(jose_constants.Algorithms.HASHES)
    SUPPORTED = jose_constants.Algorithms.SUPPORTED.union(KMS_ASYMMETRIC_SIGNING)
    ALL = jose_constants.Algorithms.ALL.union(SUPPORTED)


# monkey patching jose.constants.ALGORITHMS
jose_constants.ALGORITHMS = Algorithms()
