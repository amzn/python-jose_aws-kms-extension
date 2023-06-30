from jose import JOSEError


class KMSError(JOSEError):
    """
    Base class for all custom KMS backend specific exceptions.
    """
    pass


class KMSValidationError(KMSError):
    """
    Base class for KMS validations errors.
    """
    pass


class KMSInvalidKeyFormatError(TypeError, KMSValidationError):
    """
    Exception class for invalid KMS key format.
    """
    pass


class KMSTransientError(KMSError):
    """
    Base class for KMS transient errors.
    """
    pass
