"""Tests for ECDSA and KDF utilities."""

import os
import pytest

from ecdsa import NIST256p

from biometricsig.crypto import (
    hkdf,
    hkdf_extract,
    hkdf_expand,
    derive_private_key,
    derive_keypair,
    get_public_key,
    serialize_public_key,
    deserialize_public_key,
    sign_message,
    verify_signature,
)
from biometricsig.exceptions import InvalidPublicKeyError, InvalidSignatureError


class TestHKDF:
    """Test HKDF key derivation function."""

    def test_hkdf_produces_correct_length(self):
        ikm = os.urandom(32)
        for length in [16, 32, 64, 128]:
            result = hkdf(ikm, length)
            assert len(result) == length

    def test_hkdf_deterministic(self):
        ikm = b"input keying material"
        salt = b"salt value"
        info = b"context info"

        result1 = hkdf(ikm, 32, salt, info)
        result2 = hkdf(ikm, 32, salt, info)

        assert result1 == result2

    def test_hkdf_different_inputs_different_outputs(self):
        ikm1 = b"input 1"
        ikm2 = b"input 2"

        result1 = hkdf(ikm1, 32)
        result2 = hkdf(ikm2, 32)

        assert result1 != result2

    def test_hkdf_extract(self):
        salt = b"salt"
        ikm = b"input"

        prk = hkdf_extract(salt, ikm)
        assert len(prk) == 32  # SHA-256 output

    def test_hkdf_expand(self):
        prk = os.urandom(32)
        info = b"info"

        okm = hkdf_expand(prk, info, 64)
        assert len(okm) == 64


class TestKeyDerivation:
    """Test ECDSA key derivation from fuzzy extractor output."""

    def test_derive_private_key_produces_valid_key(self):
        fuzzy_key = os.urandom(32)
        private_key = derive_private_key(fuzzy_key)

        assert private_key is not None
        assert private_key.curve == NIST256p

    def test_derive_private_key_deterministic(self):
        fuzzy_key = os.urandom(32)

        key1 = derive_private_key(fuzzy_key)
        key2 = derive_private_key(fuzzy_key)

        assert key1.to_string() == key2.to_string()

    def test_different_fuzzy_keys_produce_different_private_keys(self):
        key1 = derive_private_key(os.urandom(32))
        key2 = derive_private_key(os.urandom(32))

        assert key1.to_string() != key2.to_string()

    def test_derive_keypair(self):
        fuzzy_key = os.urandom(32)
        private_key, public_key = derive_keypair(fuzzy_key)

        assert private_key is not None
        assert public_key is not None
        assert public_key == get_public_key(private_key)


class TestPublicKeySerialization:
    """Test public key serialization and deserialization."""

    def test_serialize_produces_compressed_format(self):
        _, public_key = derive_keypair(os.urandom(32))
        serialized = serialize_public_key(public_key)

        # Compressed P-256 public key is 33 bytes
        assert len(serialized) == 33
        # First byte should be 0x02 or 0x03
        assert serialized[0] in (0x02, 0x03)

    def test_deserialize_compressed_key(self):
        _, public_key = derive_keypair(os.urandom(32))
        serialized = serialize_public_key(public_key)
        restored = deserialize_public_key(serialized)

        assert restored.to_string() == public_key.to_string()

    def test_roundtrip_serialization(self):
        for _ in range(5):  # Test multiple random keys
            _, public_key = derive_keypair(os.urandom(32))
            serialized = serialize_public_key(public_key)
            restored = deserialize_public_key(serialized)

            assert restored.to_string() == public_key.to_string()

    def test_deserialize_invalid_length(self):
        with pytest.raises(InvalidPublicKeyError):
            deserialize_public_key(b"short")

    def test_deserialize_invalid_point(self):
        # Invalid compressed point (wrong prefix or not on curve)
        invalid = b"\x04" + b"\x00" * 32  # Wrong prefix for 33-byte key
        with pytest.raises(InvalidPublicKeyError):
            deserialize_public_key(invalid)


class TestSigningAndVerification:
    """Test ECDSA signing and verification."""

    def test_sign_and_verify_success(self):
        private_key, public_key = derive_keypair(os.urandom(32))
        message = b"Hello, World!"

        signature = sign_message(private_key, message)
        assert verify_signature(public_key, message, signature)

    def test_verify_fails_with_wrong_message(self):
        private_key, public_key = derive_keypair(os.urandom(32))
        message = b"Original message"
        wrong_message = b"Tampered message"

        signature = sign_message(private_key, message)
        assert not verify_signature(public_key, wrong_message, signature)

    def test_verify_fails_with_wrong_key(self):
        private_key1, _ = derive_keypair(os.urandom(32))
        _, public_key2 = derive_keypair(os.urandom(32))
        message = b"Hello"

        signature = sign_message(private_key1, message)
        assert not verify_signature(public_key2, message, signature)

    def test_signature_is_deterministic(self):
        """RFC 6979 deterministic k-generation should produce same signature."""
        private_key, _ = derive_keypair(os.urandom(32))
        message = b"Same message"

        sig1 = sign_message(private_key, message)
        sig2 = sign_message(private_key, message)

        assert sig1 == sig2

    def test_different_messages_different_signatures(self):
        private_key, _ = derive_keypair(os.urandom(32))

        sig1 = sign_message(private_key, b"Message 1")
        sig2 = sign_message(private_key, b"Message 2")

        assert sig1 != sig2

    def test_sign_empty_message(self):
        """Empty messages should be signable."""
        private_key, public_key = derive_keypair(os.urandom(32))
        message = b""

        signature = sign_message(private_key, message)
        assert verify_signature(public_key, message, signature)

    def test_sign_large_message(self):
        """Large messages should be signable (hash is used internally)."""
        private_key, public_key = derive_keypair(os.urandom(32))
        message = os.urandom(1024 * 1024)  # 1 MB

        signature = sign_message(private_key, message)
        assert verify_signature(public_key, message, signature)

    def test_invalid_signature_format(self):
        _, public_key = derive_keypair(os.urandom(32))
        message = b"Hello"

        # Corrupted/invalid signature bytes - may return False or raise InvalidSignatureError
        invalid_sig = b"not a valid signature"
        try:
            result = verify_signature(public_key, message, invalid_sig)
            assert result is False  # Invalid signatures should not verify
        except InvalidSignatureError:
            pass  # Also acceptable to raise exception


class TestCryptoIntegration:
    """Integration tests for the full crypto flow."""

    def test_full_flow_with_fuzzy_key(self):
        """Test complete flow from fuzzy key to signature verification."""
        # Simulate fuzzy extractor output
        fuzzy_key = os.urandom(32)

        # Derive keys
        private_key, public_key = derive_keypair(fuzzy_key)

        # Serialize public key (this is what gets stored/shared)
        vk_bytes = serialize_public_key(public_key)

        # Sign a message
        message = b"Transaction: send 100 tokens"
        signature = sign_message(private_key, message)

        # Verify using deserialized public key
        restored_pk = deserialize_public_key(vk_bytes)
        assert verify_signature(restored_pk, message, signature)

    def test_same_fuzzy_key_produces_consistent_signatures(self):
        """Same fuzzy key should produce same signatures."""
        fuzzy_key = os.urandom(32)
        message = b"Test message"

        # First derivation and signing
        pk1, _ = derive_keypair(fuzzy_key)
        sig1 = sign_message(pk1, message)

        # Second derivation and signing
        pk2, _ = derive_keypair(fuzzy_key)
        sig2 = sign_message(pk2, message)

        assert sig1 == sig2

