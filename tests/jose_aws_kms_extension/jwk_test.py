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

from unittest import mock

import pytest
from _pytest.fixtures import FixtureRequest
from jose.backends import DIRKey
from jose.backends.base import Key
from jose.constants import ALGORITHMS
from jose.jwk import get_key, construct

from jose_aws_kms_extension.backends.kms.asymmetric.signing import BotoKMSAsymmetricSigningKey
from jose_aws_kms_extension.backends.kms.symmetric.encryption import BotoKMSSymmetricEncryptionKey


@pytest.fixture(params=ALGORITHMS.KMS_ASYMMETRIC_SIGNING)
def valid_asymmetric_signing_algorithm(request: FixtureRequest) -> str:
    return request.param


def test_get_key__with_symmetric_default_algorithm__should_return_boto_symmetric_encryption_key() -> None:
    key_class = get_key(ALGORITHMS.SYMMETRIC_DEFAULT)

    assert key_class is BotoKMSSymmetricEncryptionKey


def test_get_key__with_kms_asymmetric_signing_algorithm__should_return_boto_asymmetric_signing_key(
    valid_asymmetric_signing_algorithm: str
) -> None:
    key_class = get_key(valid_asymmetric_signing_algorithm)

    assert key_class is BotoKMSAsymmetricSigningKey


@mock.patch('jose_aws_kms_extension.jwk.jose_jwk_get_key')
def test_get_key__with_another_algorithm__should_call_jose_jwk_get_key(mock_jose_jwk_get_key: mock.MagicMock) -> None:
    mock_jose_jwk_get_key.return_value = mock.MagicMock(spec=DIRKey)

    key_class = get_key(ALGORITHMS.DIR)

    assert key_class is mock_jose_jwk_get_key.return_value


def test_construct__with_key_object__should_return_same_object() -> None:
    input_key = mock.MagicMock(spec=Key)

    output_key = construct(key_data=input_key)

    assert output_key is input_key


@mock.patch('jose_aws_kms_extension.jwk.jose_jwk_construct')
def test_construct__with_non_key_object_key__should_call_jose_jwk_construct(
    mock_jose_jwk_construct: mock.MagicMock
) -> None:
    mock_jose_jwk_construct.return_value = mock.MagicMock(spec=Key)
    input_key = mock.MagicMock()
    input_algorithm = mock.MagicMock()

    output_key = construct(key_data=input_key, algorithm=input_algorithm)

    mock_jose_jwk_construct.assert_called_once_with(key_data=input_key, algorithm=input_algorithm)
    assert output_key is mock_jose_jwk_construct.return_value
