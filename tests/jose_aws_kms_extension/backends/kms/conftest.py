from typing import Generator
from unittest import mock

import pytest
from mypy_boto3_kms import KMSClient


@pytest.fixture
def mock_kms_client() -> mock.MagicMock:
    return mock.MagicMock(spec=KMSClient)


@pytest.fixture
def mock_validate_key_format() -> Generator[mock.MagicMock, None, None]:
    patcher = mock.patch("jose_aws_kms_extension.backends.kms.utils.validate_key_format")
    mocked_func = patcher.start()

    yield mocked_func

    patcher.stop()
