"""
biometricsig - Biometric-based signing using fuzzy extractors and ECDSA.

This library provides a simple API for generating cryptographic signatures
from biometric data. It combines fuzzy extractors (for deriving stable keys
from noisy biometric inputs) with ECDSA (for digital signatures).

The library is biometric-agnostic: it treats biometric data as opaque bytes.
The caller is responsible for feature extraction, normalization, and ensuring
sufficient stability between enrollment and signing samples.

Quick Start:
    >>> from biometricsig import enroll, sign, verify
    >>>
    >>> # Enrollment (store vk publicly, sketch securely)
    >>> vk, sketch = enroll(biometric_bytes)
    >>>
    >>> # Signing (with similar biometric sample)
    >>> signature = sign(biometric_bytes, sketch, message)
    >>>
    >>> # Verification (anyone can verify with vk)
    >>> is_valid = verify(vk, message, signature)

For more control, use the BiometricSigner class:
    >>> from biometricsig import BiometricSigner
    >>>
    >>> signer = BiometricSigner(hamming_threshold=16)
    >>> vk, sketch = signer.enroll(biometric_bytes)

See Also:
    - api.py: Main API functions
    - fuzzy.py: Fuzzy extractor implementation details
    - crypto.py: ECDSA and KDF utilities
    - exceptions.py: Custom exception types
"""

__version__ = "0.1.0"
__author__ = "BiometricSig Contributors"

# Public API - main functions
from .api import enroll, sign, verify, BiometricSigner

# Exceptions for error handling
from .exceptions import (
    BiometricSigError,
    BiometricMismatchError,
    InvalidSketchError,
    InvalidPublicKeyError,
    InvalidSignatureError,
    EnrollmentError,
)

# Fuzzy extractor types (for advanced usage)
from .fuzzy import FuzzyExtractorParams, Sketch

__all__ = [
    # Version
    "__version__",
    # Main API
    "enroll",
    "sign",
    "verify",
    "BiometricSigner",
    # Exceptions
    "BiometricSigError",
    "BiometricMismatchError",
    "InvalidSketchError",
    "InvalidPublicKeyError",
    "InvalidSignatureError",
    "EnrollmentError",
    # Types
    "FuzzyExtractorParams",
    "Sketch",
]

