from typing import Tuple

from jose.backends.base import Key
from jose.jwe import _get_key_wrap_cek as jose_jwe_get_key_wrap_cek
from jose import jwe as jose_jwe

from jose_aws_kms_extension.backends.kms.symmetric.encryption import KmsSymmetricEncryptionKey


def _get_key_wrap_cek(enc: str, key: Key) -> Tuple[bytes, bytes]:
    """
    Override of :func:`~jose.jwe._get_key_wrap_cek` function, to allow AWS KMS related keys.
    :param enc: Encryption method encrypting content.
    :param key: Key for encrypting CEK.
    :return: Tuple of CEK bytes and wrapped/encrypted CEK bytes.
    """

    if isinstance(key, KmsSymmetricEncryptionKey):
        return key.generate_data_key(enc=enc)
    else:
        return jose_jwe_get_key_wrap_cek(enc=enc, key=key)


jose_jwe._get_key_wrap_cek = _get_key_wrap_cek
