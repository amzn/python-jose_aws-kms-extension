from unittest import mock

import pytest
from mypy_boto3_kms import KMSClient


@pytest.fixture
def mock_kms_client() -> mock.MagicMock:
    return mock.MagicMock(spec=KMSClient)
