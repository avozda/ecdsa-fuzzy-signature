"""Tests for the public API (enroll, sign, verify)."""

import os
import pytest

from biometricsig import (
    enroll,
    sign,
    verify,
    BiometricSigner,
    BiometricMismatchError,
    InvalidPublicKeyError,
    InvalidSignatureError,
    InvalidSketchError,
)


# Use smaller biometric size for faster tests
DEFAULT_TEST_BIOMETRIC_SIZE = 16


def flip_bits(data: bytes, positions: list[int]) -> bytes:
    """Flip specific bits in a byte array."""
    result = bytearray(data)
    for pos in positions:
        byte_idx = pos // 8
        bit_idx = pos % 8
        if byte_idx < len(result):
            result[byte_idx] ^= (1 << bit_idx)
    return bytes(result)


def random_biometric(length: int = DEFAULT_TEST_BIOMETRIC_SIZE) -> bytes:
    """Generate random bytes simulating a biometric sample."""
    return os.urandom(length)


class TestEnroll:
    """Test enrollment functionality."""

    def test_enroll_returns_vk_and_sketch(self, enrolled_data):
        """Test that enrollment returns valid vk and sketch."""
        assert isinstance(enrolled_data["vk"], bytes)
        assert isinstance(enrolled_data["sketch"], bytes)
        assert len(enrolled_data["vk"]) > 0
        assert len(enrolled_data["sketch"]) > 0

    def test_enroll_vk_is_compressed_public_key(self, enrolled_data):
        """Test that vk is a compressed ECDSA public key."""
        vk = enrolled_data["vk"]
        # Compressed P-256 public key is 33 bytes
        assert len(vk) == 33
        assert vk[0] in (0x02, 0x03)

    def test_enroll_empty_biometric_raises(self):
        with pytest.raises(ValueError):
            enroll(b"")


class TestSign:
    """Test signing functionality."""

    def test_sign_with_same_biometric(self, enrolled_data):
        """Test signing with the enrollment biometric."""
        signature = sign(
            enrolled_data["biometric"],
            enrolled_data["sketch"],
            b"Hello, World!"
        )
        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_sign_with_similar_biometric(self, enrolled_data):
        """Signing should work with biometric within Hamming threshold."""
        biometric = enrolled_data["biometric"]
        # Flip a few bits (fewer than threshold of 8)
        noisy = flip_bits(biometric, [0, 8, 16])
        message = b"Test message"

        signature = sign(noisy, enrolled_data["sketch"], message)
        assert verify(enrolled_data["vk"], message, signature)

    def test_sign_with_different_biometric_raises(self, enrolled_data):
        """Signing should fail with completely different biometric."""
        # Create a biometric that is maximally different (all bits flipped)
        different = bytes(b ^ 0xFF for b in enrolled_data["biometric"])
        with pytest.raises(BiometricMismatchError):
            sign(different, enrolled_data["sketch"], b"Test message")

    def test_sign_empty_biometric_raises(self, enrolled_data):
        with pytest.raises(ValueError):
            sign(b"", enrolled_data["sketch"], b"message")

    def test_sign_empty_sketch_raises(self):
        biometric = random_biometric()
        with pytest.raises(ValueError):
            sign(biometric, b"", b"message")

    def test_sign_empty_message(self, enrolled_data):
        """Empty messages should be signable."""
        signature = sign(
            enrolled_data["biometric"],
            enrolled_data["sketch"],
            b""
        )
        assert verify(enrolled_data["vk"], b"", signature)

    def test_sign_invalid_sketch_raises(self):
        biometric = random_biometric()
        with pytest.raises(InvalidSketchError):
            sign(biometric, b"invalid", b"message")


class TestVerify:
    """Test verification functionality."""

    def test_verify_valid_signature(self, enrolled_data):
        signature = sign(
            enrolled_data["biometric"],
            enrolled_data["sketch"],
            b"Hello, World!"
        )
        assert verify(enrolled_data["vk"], b"Hello, World!", signature) is True

    def test_verify_wrong_message(self, enrolled_data):
        signature = sign(
            enrolled_data["biometric"],
            enrolled_data["sketch"],
            b"Original"
        )
        assert verify(enrolled_data["vk"], b"Tampered", signature) is False

    def test_verify_empty_vk_raises(self):
        with pytest.raises(ValueError):
            verify(b"", b"message", b"signature")

    def test_verify_empty_signature_raises(self, enrolled_data):
        with pytest.raises(ValueError):
            verify(enrolled_data["vk"], b"message", b"")

    def test_verify_invalid_vk_raises(self):
        with pytest.raises(InvalidPublicKeyError):
            verify(b"invalid_key", b"message", b"signature")


class TestBiometricSigner:
    """Test the class-based BiometricSigner interface."""

    def test_signer_basic_flow(self):
        """Test basic signer flow with a fresh enrollment."""
        signer = BiometricSigner()
        biometric = random_biometric()
        message = b"Test message"

        vk, sketch = signer.enroll(biometric)
        signature = signer.sign(biometric, sketch, message)
        assert signer.verify(vk, message, signature)


class TestIntegration:
    """End-to-end integration tests."""

    def test_full_enrollment_sign_verify_flow(self, enrolled_data):
        """Test complete flow from enrollment through verification."""
        message = b"I authorize this transaction"
        signature = sign(
            enrolled_data["biometric"],
            enrolled_data["sketch"],
            message
        )
        assert verify(enrolled_data["vk"], message, signature)

    def test_multiple_signatures_same_biometric(self, enrolled_data):
        """Multiple signatures from same biometric should all verify."""
        messages = [b"Message 1", b"Message 2", b"Message 3"]
        signatures = [
            sign(enrolled_data["biometric"], enrolled_data["sketch"], msg)
            for msg in messages
        ]

        for msg, sig in zip(messages, signatures):
            assert verify(enrolled_data["vk"], msg, sig)

    def test_cross_signature_verification_fails(self, enrolled_data):
        """Signatures should not verify against wrong messages."""
        sig1 = sign(enrolled_data["biometric"], enrolled_data["sketch"], b"Message 1")
        sig2 = sign(enrolled_data["biometric"], enrolled_data["sketch"], b"Message 2")

        assert not verify(enrolled_data["vk"], b"Message 2", sig1)
        assert not verify(enrolled_data["vk"], b"Message 1", sig2)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_binary_message(self, enrolled_data):
        """Test signing binary data."""
        binary_message = bytes(range(256))
        signature = sign(
            enrolled_data["biometric"],
            enrolled_data["sketch"],
            binary_message
        )
        assert verify(enrolled_data["vk"], binary_message, signature)

    def test_unicode_in_message(self, enrolled_data):
        """Test signing UTF-8 encoded message."""
        unicode_message = "Hello 世界 🌍".encode("utf-8")
        signature = sign(
            enrolled_data["biometric"],
            enrolled_data["sketch"],
            unicode_message
        )
        assert verify(enrolled_data["vk"], unicode_message, signature)

    def test_signature_length(self, enrolled_data):
        """Verify signature has expected length for ECDSA P-256."""
        signature = sign(
            enrolled_data["biometric"],
            enrolled_data["sketch"],
            b"test"
        )
        # ECDSA P-256 signature is ~64 bytes (r, s each 32 bytes)
        assert 64 <= len(signature) <= 72
