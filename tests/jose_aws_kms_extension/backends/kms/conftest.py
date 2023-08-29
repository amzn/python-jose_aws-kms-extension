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

from types import SimpleNamespace
from typing import Generator, Dict, Type, Tuple, Sequence
from unittest import mock

import botocore
import pytest
from botocore.errorfactory import BaseClientExceptions, ClientExceptionsFactory
from botocore.model import ServiceModel
from mypy_boto3_kms import KMSClient
from mypy_boto3_kms.client import BotocoreClientError

from jose_aws_kms_extension import exceptions
from jose_aws_kms_extension.backends.kms import constants as kms_be_consts


_KMS_ERROR_CLS_TO_DEFAULT_MSG_DICT: Dict[Type[exceptions.KMSError], str] = {
    exceptions.KMSValidationError: kms_be_consts.DEFAULT_KMS_VALIDATION_ERROR_MESSAGE,
    exceptions.KMSTransientError: kms_be_consts.DEFAULT_KMS_TRANSIENT_ERROR_MESSAGE,
}
_DEFAULT_PARM_VALUES_WITHOUT_MESSAGE: Sequence[Tuple[str, Type[exceptions.KMSError]]] = [
    ('NotFoundException', exceptions.KMSValidationError),
    ('DisabledException', exceptions.KMSValidationError),
    ('InvalidKeyUsageException', exceptions.KMSValidationError),
    ('KMSInvalidStateException', exceptions.KMSValidationError),
    ('InvalidGrantTokenException', exceptions.KMSValidationError),
    ('DependencyTimeoutException', exceptions.KMSTransientError),
    ('KMSInternalException', exceptions.KMSTransientError),
    ('KeyUnavailableException', exceptions.KMSTransientError),
]
PARAMETRIZED_KMS_ERROR_TEST_CONSTS = SimpleNamespace(
    DEFAULT_PARAMS=['kms_exception_from_class_name', 'jose_kms_exception_class', 'jose_kms_exception_message'],
    DEFAULT_INDIRECT_PARAMS=['kms_exception_from_class_name'],
    DEFAULT_PARAM_VALUES_WITHOUT_MESSAGE=_DEFAULT_PARM_VALUES_WITHOUT_MESSAGE,
    DEFAULT_PARAM_VALUES=[
        param_values + (_KMS_ERROR_CLS_TO_DEFAULT_MSG_DICT[param_values[1]],)
        for param_values in _DEFAULT_PARM_VALUES_WITHOUT_MESSAGE
    ],
)


@pytest.fixture
def mock_validate_key_format() -> Generator[mock.MagicMock, None, None]:
    patcher = mock.patch("jose_aws_kms_extension.backends.kms.utils.validate_key_format")
    mocked_func = patcher.start()

    yield mocked_func

    patcher.stop()


@pytest.fixture
def kms_service_model() -> ServiceModel:
    return botocore.session.get_session().get_service_model('kms')


@pytest.fixture
def client_exceptions_factory() -> ClientExceptionsFactory:
    return botocore.errorfactory.ClientExceptionsFactory()


@pytest.fixture
def kms_client_exceptions(
    kms_service_model: ServiceModel, client_exceptions_factory: ClientExceptionsFactory
) -> BaseClientExceptions:
    return client_exceptions_factory.create_client_exceptions(kms_service_model)


@pytest.fixture
def mock_kms_client(kms_client_exceptions: BaseClientExceptions) -> mock.MagicMock:
    mock_kms_client = mock.MagicMock(spec=KMSClient)

    for exception_class_name in [
        'KMSInvalidSignatureException', 'NotFoundException', 'DisabledException', 'KeyUnavailableException',
        'InvalidKeyUsageException', 'KMSInvalidStateException', 'InvalidCiphertextException', 'IncorrectKeyException',
        'DependencyTimeoutException', 'InvalidGrantTokenException', 'KMSInternalException'
    ]:
        setattr(mock_kms_client.exceptions, exception_class_name, getattr(kms_client_exceptions, exception_class_name))

    return mock_kms_client


@pytest.fixture
def error_response() -> Dict:
    return {"Error": {"Code": "Test code"}}


@pytest.fixture
def operation_name() -> str:
    return 'Test operation'


@pytest.fixture
def kms_exception_from_class_name(
    request: pytest.FixtureRequest, kms_client_exceptions: BaseClientExceptions, error_response: Dict,
    operation_name: str
) -> BotocoreClientError:
    exception_class: Type[BotocoreClientError] = getattr(kms_client_exceptions, request.param)
    return exception_class(error_response, operation_name)
