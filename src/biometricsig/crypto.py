"""
ECDSA and KDF utilities for biometric-based signing.

This module provides cryptographic primitives for deriving ECDSA keys
from fuzzy extractor outputs and performing signing/verification.

The ECDSA implementation uses the python-ecdsa library with the
secp256r1 (NIST P-256) curve by default, which provides 128-bit
security level.

Security Note:
    The private key is derived deterministically from the fuzzy extractor
    output using HKDF. This means the same biometric input will always
    produce the same key pair (given the same sketch).
"""

import hashlib
import hmac
from typing import Tuple

from ecdsa import NIST256p, SigningKey, VerifyingKey, BadSignatureError
from ecdsa.util import number_to_string, string_to_number

from .exceptions import InvalidPublicKeyError, InvalidSignatureError


# Default curve for ECDSA operations
DEFAULT_CURVE = NIST256p

# Hash function for ECDSA signing
HASH_FUNC = hashlib.sha256

# HKDF parameters
HKDF_INFO = b"biometricsig-ecdsa-key-v1"
HKDF_SALT = b"biometricsig-salt-v1"


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """
    HKDF-Extract: Extract a pseudorandom key from input keying material.

    Args:
        salt: Non-secret salt value (can be empty/zero).
        ikm: Input keying material.

    Returns:
        Pseudorandom key (PRK).
    """
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-Expand: Expand pseudorandom key to desired length.

    Args:
        prk: Pseudorandom key from HKDF-Extract.
        info: Context/application-specific info.
        length: Desired output length in bytes.

    Returns:
        Output keying material of specified length.
    """
    hash_len = 32  # SHA-256 output length
    n = (length + hash_len - 1) // hash_len

    okm = b""
    t = b""

    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t

    return okm[:length]


def hkdf(ikm: bytes, length: int, salt: bytes = HKDF_SALT, info: bytes = HKDF_INFO) -> bytes:
    """
    HKDF key derivation function (RFC 5869).

    Derives a cryptographically strong key from input keying material.

    Args:
        ikm: Input keying material (e.g., from fuzzy extractor).
        length: Desired output length in bytes.
        salt: Optional salt value.
        info: Optional context info.

    Returns:
        Derived key of specified length.
    """
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


def derive_private_key(fuzzy_key: bytes, curve=DEFAULT_CURVE) -> SigningKey:
    """
    Derive an ECDSA private key from a fuzzy extractor key.

    The private key is derived by:
    1. Expanding the fuzzy key using HKDF to get enough bytes
    2. Interpreting the result as an integer
    3. Reducing modulo the curve order to get a valid private scalar

    Args:
        fuzzy_key: Key output from fuzzy extractor (at least 32 bytes).
        curve: ECDSA curve to use (default: NIST P-256).

    Returns:
        ECDSA SigningKey object.

    Security Note:
        The private key derivation is deterministic - the same fuzzy_key
        always produces the same private key. This is intentional for
        reproducibility but means the fuzzy_key must have sufficient entropy.
    """
    # Get curve order byte length
    order = curve.order
    order_bytes = (order.bit_length() + 7) // 8

    # Expand fuzzy key using HKDF to get enough material
    # We get extra bytes to ensure uniform distribution after modular reduction
    expanded = hkdf(fuzzy_key, order_bytes + 16)

    # Convert to integer and reduce modulo curve order
    # The +16 extra bytes ensures the bias from modular reduction is negligible
    scalar = string_to_number(expanded) % order

    # Ensure scalar is not 0 (astronomically unlikely with proper entropy)
    if scalar == 0:
        scalar = 1

    # Create signing key from the scalar
    secexp_bytes = number_to_string(scalar, order)
    return SigningKey.from_string(secexp_bytes, curve=curve)


def get_public_key(private_key: SigningKey) -> VerifyingKey:
    """
    Get the public key corresponding to a private key.

    Args:
        private_key: ECDSA SigningKey.

    Returns:
        ECDSA VerifyingKey.
    """
    return private_key.get_verifying_key()


def serialize_public_key(public_key: VerifyingKey) -> bytes:
    """
    Serialize a public key to bytes (compressed format).

    Uses SEC1 compressed point encoding (33 bytes for P-256).

    Args:
        public_key: ECDSA VerifyingKey.

    Returns:
        Compressed public key bytes.
    """
    # Get the point and encode in compressed format
    point = public_key.pubkey.point
    x = point.x()
    y = point.y()

    # Compressed format: 0x02 or 0x03 prefix + x-coordinate
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    x_bytes = number_to_string(x, public_key.curve.order)

    return prefix + x_bytes


def deserialize_public_key(data: bytes, curve=DEFAULT_CURVE) -> VerifyingKey:
    """
    Deserialize a public key from bytes.

    Supports both compressed (33 bytes) and uncompressed (65 bytes) formats.

    Args:
        data: Public key bytes.
        curve: ECDSA curve (default: NIST P-256).

    Returns:
        ECDSA VerifyingKey.

    Raises:
        InvalidPublicKeyError: If the data cannot be parsed as a valid public key.
    """
    try:
        if len(data) == 33:
            # Compressed format
            return VerifyingKey.from_string(data, curve=curve)
        elif len(data) == 65:
            # Uncompressed format
            return VerifyingKey.from_string(data, curve=curve)
        else:
            raise InvalidPublicKeyError(
                f"Invalid public key length: expected 33 or 65 bytes, got {len(data)}"
            )
    except Exception as e:
        if isinstance(e, InvalidPublicKeyError):
            raise
        raise InvalidPublicKeyError(f"Failed to deserialize public key: {e}") from e


def sign_message(private_key: SigningKey, message: bytes) -> bytes:
    """
    Sign a message with an ECDSA private key.

    Uses SHA-256 as the hash function and returns a DER-encoded signature.

    Args:
        private_key: ECDSA SigningKey.
        message: Message bytes to sign.

    Returns:
        DER-encoded signature bytes.
    """
    # Sign with SHA-256 hash, deterministic RFC 6979 k-generation
    signature = private_key.sign_deterministic(
        message,
        hashfunc=HASH_FUNC,
    )
    return signature


def verify_signature(public_key: VerifyingKey, message: bytes, signature: bytes) -> bool:
    """
    Verify an ECDSA signature.

    Args:
        public_key: ECDSA VerifyingKey.
        message: Original message bytes.
        signature: Signature bytes to verify.

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        InvalidSignatureError: If the signature format is invalid.
    """
    try:
        public_key.verify(signature, message, hashfunc=HASH_FUNC)
        return True
    except BadSignatureError:
        return False
    except Exception as e:
        raise InvalidSignatureError(f"Invalid signature format: {e}") from e


def derive_keypair(fuzzy_key: bytes, curve=DEFAULT_CURVE) -> Tuple[SigningKey, VerifyingKey]:
    """
    Derive a complete ECDSA keypair from a fuzzy extractor key.

    Convenience function that derives both private and public keys.

    Args:
        fuzzy_key: Key from fuzzy extractor.
        curve: ECDSA curve (default: NIST P-256).

    Returns:
        Tuple of (SigningKey, VerifyingKey).
    """
    private_key = derive_private_key(fuzzy_key, curve)
    public_key = get_public_key(private_key)
    return private_key, public_key

