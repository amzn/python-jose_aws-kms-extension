import contextlib
import re
import typing

from mypy_boto3_kms import KMSClient

from jose_aws_kms_extension import exceptions
from jose_aws_kms_extension.backends.kms import constants as kms_be_consts


def validate_key_format(key: str) -> None:
    """
    Validates if the passed :param:`key` is in the correct format.

    :param key: AWS KMS key (it can be a key-id, key-id ARN, key-alias or key-alias ARN).

    :raise KMSInvalidKeyFormatError: If the key format doesn't match to a KMS specific key format.
    """

    if not isinstance(key, str) or not re.match(r'^\S+$', key):
        raise exceptions.KMSInvalidKeyFormatError(
            "Provided key isn't supported by KMS. "
            "Expected a string with key-id, key-id ARN, key-alias or key-alias ARN."
        )


@contextlib.contextmanager
def default_kms_exception_handing(
    kms_client: KMSClient,
    validation_error_message: str = kms_be_consts.DEFAULT_KMS_VALIDATION_ERROR_MESSAGE,
    transient_error_message: str = kms_be_consts.DEFAULT_KMS_TRANSIENT_ERROR_MESSAGE
) -> typing.Iterator[None]:
    """
    This context-manger/decorator handles common exceptions thrown by :class:`~mypy_boto3_kms.KMSClient`.

    :param kms_client: :class:`~mypy_boto3_kms.KMSClient` object used for fetching boto's exception classes,
        since they are generated at the runtime.
    :param validation_error_message: (Optional) Custom validation error message string.
        It will be used with :class:`~jose_aws_kms_extension.exceptions.KMSValidationError`.
    :param transient_error_message: (Optional) Custom transient error message string.
        It will be used with :class:`~jose_aws_kms_extension.exceptions.KMSTransientError`.

    :raises jose_aws_kms_extension.exceptions.KMSValidationError: If validation exception is thrown from KMS.
    :raises jose_aws_kms_extension.exceptions.KMSTransientError: If transient exception is thrown from KMS.
    """
    try:
        yield
    except (
        kms_client.exceptions.NotFoundException,
        kms_client.exceptions.DisabledException,
        kms_client.exceptions.InvalidKeyUsageException,
        kms_client.exceptions.KMSInvalidStateException,
        kms_client.exceptions.InvalidGrantTokenException,
    ) as exc:
        raise exceptions.KMSValidationError(validation_error_message) from exc
    except (
        kms_client.exceptions.DependencyTimeoutException,
        kms_client.exceptions.KMSInternalException,
        kms_client.exceptions.KeyUnavailableException,
    ) as exc:
        raise exceptions.KMSTransientError(transient_error_message) from exc
