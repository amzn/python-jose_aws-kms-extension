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

import typing
from unittest import mock

import pytest
from mypy_boto3_kms.client import BotocoreClientError

from jose_aws_kms_extension import exceptions
from jose_aws_kms_extension.backends.kms import utils
from tests.jose_aws_kms_extension.backends.kms.conftest import PARAMETRIZED_KMS_ERROR_TEST_CONSTS


def test_validate_key_format__with_jwk_format_key__should_throw_exception() -> None:
    with pytest.raises(
        exceptions.KMSInvalidKeyFormatError,
        match=(
            "Provided key isn't supported by KMS. "
            "Expected a string with key-id, key-id ARN, key-alias or key-alias ARN."
        )
    ):
        utils.validate_key_format({"kid": "test kid", "key": "test key"})  # type: ignore[arg-type]


def test_validate_key_format__with_invalid_key_str__should_throw_exception() -> None:
    with pytest.raises(
        exceptions.KMSInvalidKeyFormatError,
        match=(
            "Provided key isn't supported by KMS. "
            "Expected a string with key-id, key-id ARN, key-alias or key-alias ARN."
        )
    ):
        utils.validate_key_format("key id with spaces")


def test_validate_key_format__with_str_format_key__should_do_nothing() -> None:
    try:
        utils.validate_key_format("valid-key-id")
    except Exception:
        pytest.fail("Exception was raised from `validate_key_format`.")


_JOSE_KMS_EXC_CLS_TO_ERROR_MSG_PARAM_DICT: typing.Dict[typing.Type[exceptions.KMSError], str] = {
    exceptions.KMSValidationError: 'validation_error_message',
    exceptions.KMSTransientError: 'transient_error_message',
}


@pytest.mark.parametrize(
    argnames=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_PARAMS,
    indirect=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_INDIRECT_PARAMS,
    argvalues=[
        param_values + ('customer exception message.',)
        for param_values in PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_PARAM_VALUES_WITHOUT_MESSAGE
    ],
)
def test_default_kms_exception_handing__with_a_default_kms_exception_n_custom_message__should_raise_jose_kms_exception(
    kms_exception_from_class_name: BotocoreClientError,
    jose_kms_exception_class: typing.Type[exceptions.KMSError],
    jose_kms_exception_message: str,
    mock_kms_client: mock.MagicMock,
) -> None:

    with pytest.raises(jose_kms_exception_class, match=jose_kms_exception_message) as exc_info:
        with utils.default_kms_exception_handing(
            kms_client=mock_kms_client,
            **{_JOSE_KMS_EXC_CLS_TO_ERROR_MSG_PARAM_DICT[jose_kms_exception_class]: jose_kms_exception_message}
        ):
            raise kms_exception_from_class_name

    assert exc_info.value.__cause__ is kms_exception_from_class_name


@pytest.mark.parametrize(
    argnames=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_PARAMS,
    indirect=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_INDIRECT_PARAMS,
    argvalues=PARAMETRIZED_KMS_ERROR_TEST_CONSTS.DEFAULT_PARAM_VALUES,
)
def test_default_kms_exception_handing__with_a_default_kms_exception__should_raise_jose_kms_exception(
    kms_exception_from_class_name: BotocoreClientError,
    jose_kms_exception_class: typing.Type[exceptions.KMSError],
    jose_kms_exception_message: str,
    mock_kms_client: mock.MagicMock,
) -> None:

    with pytest.raises(jose_kms_exception_class, match=jose_kms_exception_message) as exc_info:
        with utils.default_kms_exception_handing(kms_client=mock_kms_client):
            raise kms_exception_from_class_name

    assert exc_info.value.__cause__ is kms_exception_from_class_name


def test_default_kms_exception_handing__with_other_exception__should_reraise_same_exception(
    mock_kms_client: mock.MagicMock,
) -> None:
    test_exception_message = "test exception message"
    with pytest.raises(Exception, match=test_exception_message):
        with utils.default_kms_exception_handing(kms_client=mock_kms_client):
            raise Exception(test_exception_message)


def test_default_kms_exception_handing__with_no_exception__should_do_nothing(
    mock_kms_client: mock.MagicMock,
) -> None:
    try:
        with utils.default_kms_exception_handing(kms_client=mock_kms_client):
            assert True
    except Exception:
        pytest.fail("Exception was raised from `default_kms_exception_handing`.")
