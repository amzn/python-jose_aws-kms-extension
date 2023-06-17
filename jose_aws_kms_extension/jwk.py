from typing import Optional, Type

from jose import jwk as jose_jwk
from jose.backends.base import Key
from jose.constants import ALGORITHMS
from jose.jwk import get_key as jose_jwk_get_key

from jose_aws_kms_extension.backends.kms.symmetric.encryption import BotoKmsSymmetricEncryptionKey


def _get_key(algorithm: str) -> Optional[Type[Key]]:
    """
    Override of :func:`jose.jwk.get_key` function, to allow AWS KMS related keys.
    :param algorithm: Cryptographic algorithm for which a key is needed.
    :return: Key class.
    """

    if algorithm in ALGORITHMS.KMS_ASYMMETRIC_SIGNING:
        from jose_aws_kms_extension.backends.kms.asymmetric.signing import BotoKmsAsymmetricSigningKey

        return BotoKmsAsymmetricSigningKey
    elif algorithm == ALGORITHMS.SYMMETRIC_DEFAULT:
        return BotoKmsSymmetricEncryptionKey
    else:
        return jose_jwk_get_key(algorithm)


# monkey patching jose.jwk.get_key
jose_jwk.get_key = _get_key
