"""
Public API for biometric-based signing using fuzzy extractors and ECDSA.

This module provides the main entry points for the biometricsig library:
- enroll(): Generate a keypair from biometric data
- sign(): Sign a message using biometric data
- verify(): Verify a signature

The library is biometric-agnostic: it treats biometric data as opaque bytes.
The caller is responsible for:
- Feature extraction from raw biometric data
- Normalization and quantization to bytes
- Ensuring sufficient stability between enrollment and signing samples

Security Assumptions:
    1. The biometric input has sufficient min-entropy (recommended: ≥80 bits)
    2. The biometric feature extraction produces stable outputs
    3. The Hamming distance between enrollment and signing samples
       is within the configured threshold

Example:
    >>> # Enrollment (done once, store vk and sketch)
    >>> vk, sketch = enroll(biometric_bytes)
    >>>
    >>> # Signing (can be done multiple times with similar biometric)
    >>> signature = sign(biometric_bytes, sketch, message)
    >>>
    >>> # Verification (anyone with vk can verify)
    >>> is_valid = verify(vk, message, signature)
"""

from typing import Tuple

from .crypto import (
    derive_keypair,
    deserialize_public_key,
    serialize_public_key,
    sign_message,
    verify_signature,
)
from .exceptions import BiometricMismatchError, InvalidPublicKeyError, InvalidSignatureError
from .fuzzy import FuzzyExtractorParams, FuzzyExtractorWrapper, Sketch


# Default fuzzy extractor parameters
# Can be overridden using BiometricSigner class or function parameters
_DEFAULT_PARAMS = FuzzyExtractorParams()


def enroll(
    b: bytes,
    *,
    hamming_threshold: int | None = None,
) -> Tuple[bytes, bytes]:
    """
    Enroll a biometric sample to generate a verification key and sketch.

    This function should be called once during user enrollment. It generates
    a stable cryptographic key from the biometric input and returns:
    - A verification key (public key) that can be shared/stored publicly
    - A sketch that must be stored securely for future signing operations

    Args:
        b: Biometric sample as bytes. Must be fixed-length and derived from
           biometric data (e.g., fingerprint features, face embedding).
           The caller is responsible for feature extraction and normalization.
        hamming_threshold: Optional override for the maximum Hamming distance
            (in bits) allowed between enrollment and signing samples.
            Default is 8 bits. Higher values tolerate more noise but
            reduce security.

    Returns:
        Tuple of (vk_bytes, sketch_bytes) where:
            - vk_bytes: Serialized ECDSA public key (33 bytes, compressed)
            - sketch_bytes: Serialized fuzzy extractor sketch

    Raises:
        ValueError: If the biometric input is empty or invalid.
        EnrollmentError: If enrollment fails.

    Security Note:
        The sketch should be stored alongside the verification key but
        does not need to be kept secret. However, it may reveal some
        information about the biometric, so consider access controls.

    Example:
        >>> # Simulate biometric as 64 bytes (e.g., 512-bit feature vector)
        >>> biometric = os.urandom(64)  # In reality, from feature extraction
        >>> vk, sketch = enroll(biometric)
        >>> # Store vk (public) and sketch (for signing)
    """
    if not b:
        raise ValueError("Biometric input cannot be empty")

    # Create fuzzy extractor with specified or default parameters
    params = FuzzyExtractorParams(
        hamming_threshold=hamming_threshold or _DEFAULT_PARAMS.hamming_threshold
    )
    fe = FuzzyExtractorWrapper(params)

    # Generate key and sketch from biometric
    fuzzy_key, sketch = fe.generate(b)

    # Derive ECDSA keypair from fuzzy key
    private_key, public_key = derive_keypair(fuzzy_key)

    # Serialize outputs
    vk_bytes = serialize_public_key(public_key)
    sketch_bytes = sketch.to_bytes()

    return vk_bytes, sketch_bytes


def sign(
    b: bytes,
    sketch: bytes,
    message: bytes,
    *,
    hamming_threshold: int | None = None,
) -> bytes:
    """
    Sign a message using a biometric sample and stored sketch.

    This function recovers the private key from the biometric sample using
    the fuzzy extractor, then signs the message with ECDSA.

    Args:
        b: Biometric sample as bytes. Must be similar to the enrollment
           sample (within the Hamming distance threshold).
        sketch: The sketch bytes returned from enroll().
        message: The message to sign (arbitrary bytes).
        hamming_threshold: Optional override for Hamming threshold.
            Must match the value used during enrollment.

    Returns:
        ECDSA signature as bytes (DER-encoded, variable length ~70-72 bytes).

    Raises:
        BiometricMismatchError: If the biometric sample differs too much
            from the enrollment sample and key recovery fails.
        InvalidSketchError: If the sketch is invalid or corrupted.
        ValueError: If inputs are invalid.

    Security Note:
        The biometric sample must be "close enough" to the enrollment sample.
        If the Hamming distance exceeds the threshold, this function will
        raise BiometricMismatchError rather than produce an invalid signature.

    Example:
        >>> # User presents biometric for signing
        >>> signature = sign(biometric, stored_sketch, b"Hello, World!")
    """
    if not b:
        raise ValueError("Biometric input cannot be empty")
    if not sketch:
        raise ValueError("Sketch cannot be empty")
    if message is None:
        raise ValueError("Message cannot be None")

    # Deserialize sketch
    sketch_obj = Sketch.from_bytes(sketch)

    # Create fuzzy extractor with matching parameters
    params = FuzzyExtractorParams(
        hamming_threshold=hamming_threshold or _DEFAULT_PARAMS.hamming_threshold
    )
    fe = FuzzyExtractorWrapper(params)

    # Recover key from biometric and sketch
    # This raises BiometricMismatchError if biometric is too different
    fuzzy_key = fe.reproduce(b, sketch_obj)

    # Derive the same private key
    private_key, _ = derive_keypair(fuzzy_key)

    # Sign the message
    signature = sign_message(private_key, message)

    return signature


def verify(
    vk: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    """
    Verify an ECDSA signature against a verification key.

    This function verifies that a signature was created by the private key
    corresponding to the given verification key. It does not require any
    biometric input - anyone with the public verification key can verify.

    Args:
        vk: Verification key bytes (from enroll()).
        message: The original message that was signed.
        signature: The signature to verify (from sign()).

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        InvalidPublicKeyError: If vk cannot be parsed as a valid public key.
        InvalidSignatureError: If the signature format is invalid.

    Example:
        >>> is_valid = verify(stored_vk, b"Hello, World!", signature)
        >>> if is_valid:
        ...     print("Signature verified!")
    """
    if not vk:
        raise ValueError("Verification key cannot be empty")
    if message is None:
        raise ValueError("Message cannot be None")
    if not signature:
        raise ValueError("Signature cannot be empty")

    # Deserialize public key
    public_key = deserialize_public_key(vk)

    # Verify signature
    return verify_signature(public_key, message, signature)


class BiometricSigner:
    """
    Class-based interface for biometric signing operations.

    This class provides an alternative to the module-level functions,
    allowing you to configure parameters once and reuse them.

    Attributes:
        params: Fuzzy extractor parameters.

    Example:
        >>> signer = BiometricSigner(hamming_threshold=16)
        >>> vk, sketch = signer.enroll(biometric)
        >>> signature = signer.sign(biometric, sketch, message)
        >>> assert signer.verify(vk, message, signature)
    """

    def __init__(
        self,
        *,
        hamming_threshold: int = _DEFAULT_PARAMS.hamming_threshold,
    ):
        """
        Initialize a BiometricSigner with specific parameters.

        Args:
            hamming_threshold: Maximum Hamming distance (bits) between
                enrollment and signing biometric samples.
        """
        self.params = FuzzyExtractorParams(hamming_threshold=hamming_threshold)
        self._fe = FuzzyExtractorWrapper(self.params)

    def enroll(self, b: bytes) -> Tuple[bytes, bytes]:
        """
        Enroll a biometric sample.

        See module-level enroll() for full documentation.
        """
        if not b:
            raise ValueError("Biometric input cannot be empty")

        fuzzy_key, sketch = self._fe.generate(b)
        private_key, public_key = derive_keypair(fuzzy_key)

        vk_bytes = serialize_public_key(public_key)
        sketch_bytes = sketch.to_bytes()

        return vk_bytes, sketch_bytes

    def sign(self, b: bytes, sketch: bytes, message: bytes) -> bytes:
        """
        Sign a message using biometric data.

        See module-level sign() for full documentation.
        """
        if not b:
            raise ValueError("Biometric input cannot be empty")
        if not sketch:
            raise ValueError("Sketch cannot be empty")
        if message is None:
            raise ValueError("Message cannot be None")

        sketch_obj = Sketch.from_bytes(sketch)
        fuzzy_key = self._fe.reproduce(b, sketch_obj)
        private_key, _ = derive_keypair(fuzzy_key)

        return sign_message(private_key, message)

    def verify(self, vk: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature.

        See module-level verify() for full documentation.
        """
        # Verification doesn't depend on fuzzy extractor parameters
        return verify(vk, message, signature)

