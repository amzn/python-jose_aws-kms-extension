from typing import Optional, Type, Union

from jose import jwk as jose_jwk
from jose.backends.base import Key
from jose.constants import ALGORITHMS
from jose.jwk import (
    get_key as jose_jwk_get_key,
    construct as jose_jwk_construct,
)

from jose_aws_kms_extension.backends.kms.asymmetric.signing import BotoKMSAsymmetricSigningKey
from jose_aws_kms_extension.backends.kms.symmetric.encryption import BotoKMSSymmetricEncryptionKey


def _get_key(algorithm: str) -> Optional[Type[Key]]:
    """
    Override of :func:`~jose.jwk.get_key` function, to allow AWS KMS related keys.
    :param algorithm: Cryptographic algorithm for which a key is needed.
    :return: Key class.
    """

    if algorithm in ALGORITHMS.KMS_ASYMMETRIC_SIGNING:
        return BotoKMSAsymmetricSigningKey
    elif algorithm == ALGORITHMS.SYMMETRIC_DEFAULT:
        return BotoKMSSymmetricEncryptionKey
    else:
        return jose_jwk_get_key(algorithm)


def _construct(key_data: Union[str, dict, Key], algorithm: Optional[str] = None) -> Key:
    """
    Override of :func:`~jose.jwk.construct` method, to allow passing an externally constructed object of
    :class:`~jose.backends.base.Key`.
    :param key_data:
        Either the key-data in string or dict (JWK) format, or an object of the :class:`~jose.backends.base.Key`.
    :param algorithm: If key-data is passed (in string or dict format), then the algorithm parameter will be used for
        constructing the :class:`~jose.backends.base.Key` object.
    """
    if isinstance(key_data, Key):
        return key_data
    else:
        return jose_jwk_construct(key_data=key_data, algorithm=algorithm)


# monkey patching jose methods
jose_jwk.get_key = _get_key
jose_jwk.construct = _construct
