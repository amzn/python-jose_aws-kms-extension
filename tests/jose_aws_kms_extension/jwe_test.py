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
from unittest import mock

import pytest
from jose.backends.base import Key
from jose.constants import ALGORITHMS
from jose.jwe import _get_key_wrap_cek

from jose_aws_kms_extension.backends.kms.symmetric.encryption import KMSSymmetricEncryptionKey


@pytest.fixture
def enc() -> str:
    return ALGORITHMS.A256GCM


@pytest.fixture
def mock_kms_symmetric_encryption_key() -> mock.MagicMock:
    return mock.MagicMock(spec=KMSSymmetricEncryptionKey)


@pytest.fixture
def mock_other_key() -> mock.MagicMock:
    return mock.MagicMock(spec=Key)


@pytest.fixture
def cek_tuple() -> Tuple[bytes, bytes]:
    return b'plaintext_cek', b'encrypted_cek'


def test_get_key_wrap_cek__with_kms_symmetric_encryption_key__should_call_generate_data_key(
    enc: str, mock_kms_symmetric_encryption_key: mock.MagicMock, cek_tuple: Tuple[bytes, bytes]
) -> None:
    mock_kms_symmetric_encryption_key.generate_data_key.return_value = cek_tuple
    plaintext_cek, encrypted_cek = _get_key_wrap_cek(enc=enc, key=mock_kms_symmetric_encryption_key)

    assert plaintext_cek is cek_tuple[0]
    assert encrypted_cek is cek_tuple[1]
    mock_kms_symmetric_encryption_key.generate_data_key.assert_called_once_with(enc=enc)


@mock.patch('jose_aws_kms_extension.jwe.jose_jwe_get_key_wrap_cek')
def test_get_key_wrap_cek__with_other_key_type__should_call_jose_jwe_get_key_wrap_cek(
    mock_jose_jwe_get_key_wrap_cek: mock.MagicMock,
    enc: str,
    mock_other_key: mock.MagicMock,
    cek_tuple: Tuple[bytes, bytes]
) -> None:
    mock_jose_jwe_get_key_wrap_cek.return_value = cek_tuple
    plaintext_cek, encrypted_cek = _get_key_wrap_cek(enc=enc, key=mock_other_key)

    assert plaintext_cek is cek_tuple[0]
    assert encrypted_cek is cek_tuple[1]
    mock_jose_jwe_get_key_wrap_cek.assert_called_once_with(enc=enc, key=mock_other_key)
