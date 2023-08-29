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

from typing import Tuple

from jose.backends.base import Key
from jose.jwe import _get_key_wrap_cek as jose_jwe_get_key_wrap_cek
from jose import jwe as jose_jwe

from jose_aws_kms_extension.backends.kms.symmetric.encryption import KMSSymmetricEncryptionKey


def _get_key_wrap_cek(enc: str, key: Key) -> Tuple[bytes, bytes]:
    """
    Override of :func:`~jose.jwe._get_key_wrap_cek` function, to allow AWS KMS related keys.
    :param enc: Encryption method encrypting content.
    :param key: Key for encrypting CEK.
    :return: Tuple of CEK bytes and wrapped/encrypted CEK bytes.
    """

    if isinstance(key, KMSSymmetricEncryptionKey):
        return key.generate_data_key(enc=enc)
    else:
        return jose_jwe_get_key_wrap_cek(enc=enc, key=key)


jose_jwe._get_key_wrap_cek = _get_key_wrap_cek
