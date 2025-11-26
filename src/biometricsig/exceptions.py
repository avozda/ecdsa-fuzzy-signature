"""
Custom exceptions for the biometricsig library.

This module defines specific exceptions that can be raised during
biometric-based signing operations, enabling callers to handle
different failure modes appropriately.
"""


class BiometricSigError(Exception):
    """Base exception for all biometricsig errors."""

    pass


class BiometricMismatchError(BiometricSigError):
    """
    Raised when the fuzzy extractor fails to reconstruct the secret key.

    This typically occurs during signing when the provided biometric sample
    differs too significantly from the enrollment sample. The Hamming distance
    between the samples exceeds the error-correction threshold.

    Attributes:
        message: Explanation of why the reconstruction failed.
    """

    def __init__(self, message: str = "Biometric mismatch: unable to reconstruct secret key"):
        self.message = message
        super().__init__(self.message)


class InvalidSketchError(BiometricSigError):
    """
    Raised when the provided sketch is invalid or corrupted.

    This can occur if the sketch bytes cannot be deserialized or
    have been tampered with.
    """

    def __init__(self, message: str = "Invalid or corrupted sketch data"):
        self.message = message
        super().__init__(self.message)


class InvalidPublicKeyError(BiometricSigError):
    """
    Raised when the provided public key bytes are invalid.

    This occurs during verification if the public key cannot be
    reconstructed from the provided bytes.
    """

    def __init__(self, message: str = "Invalid public key bytes"):
        self.message = message
        super().__init__(self.message)


class InvalidSignatureError(BiometricSigError):
    """
    Raised when the provided signature bytes are malformed.

    This is distinct from a verification failure - it indicates
    the signature cannot even be parsed, not that it failed to verify.
    """

    def __init__(self, message: str = "Invalid or malformed signature"):
        self.message = message
        super().__init__(self.message)


class EnrollmentError(BiometricSigError):
    """
    Raised when enrollment fails due to insufficient entropy or other issues.

    This can occur if the biometric input does not meet the minimum
    requirements for the fuzzy extractor.
    """

    def __init__(self, message: str = "Enrollment failed"):
        self.message = message
        super().__init__(self.message)

