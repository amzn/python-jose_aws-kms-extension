from jose import JOSEError


class KMSError(JOSEError):
    """
    Base class for all custom KMS backend specific exceptions.
    """
    pass


class KMSValidationError(KMSError):
    """
    Base class KMS validations errors.
    """
    pass


class KMSInvalidKeyFormatError(TypeError, KMSValidationError):
    """
    Exception class for invalid KMS key format.
    """
    pass
