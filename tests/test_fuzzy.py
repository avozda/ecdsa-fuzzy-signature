"""Tests for fuzzy extractor wrapper."""

import os
import pytest

from biometricsig.fuzzy import (
    FuzzyExtractorParams,
    FuzzyExtractorWrapper,
    Sketch,
    generate,
    reproduce,
)
from biometricsig.exceptions import BiometricMismatchError, InvalidSketchError


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


class TestFuzzyExtractorParams:
    """Test fuzzy extractor parameter validation."""

    def test_default_params(self):
        params = FuzzyExtractorParams()
        assert params.hamming_threshold == 8

    def test_custom_params(self):
        params = FuzzyExtractorParams(hamming_threshold=16)
        assert params.hamming_threshold == 16

    def test_negative_hamming_threshold(self):
        with pytest.raises(ValueError, match="hamming_threshold"):
            FuzzyExtractorParams(hamming_threshold=-1)

    def test_params_immutable(self):
        """Verify params are frozen (immutable)."""
        params = FuzzyExtractorParams()
        with pytest.raises(Exception):  # FrozenInstanceError
            params.hamming_threshold = 64


class TestSketch:
    """Test sketch serialization and deserialization."""

    def test_sketch_roundtrip(self):
        import numpy as np
        # Create a mock helper tuple similar to what fuzzy_extractor produces
        helper = (
            np.array([[1, 2, 3], [4, 5, 6]], dtype=np.uint8),
            np.array([[7, 8, 9]], dtype=np.uint8),
        )
        original = Sketch(helper=helper, input_length=64)
        serialized = original.to_bytes()
        restored = Sketch.from_bytes(serialized)

        assert restored.input_length == original.input_length
        assert len(restored.helper) == len(original.helper)
        for orig_arr, rest_arr in zip(original.helper, restored.helper):
            assert np.array_equal(orig_arr, rest_arr)

    def test_sketch_from_bytes_too_short(self):
        with pytest.raises(InvalidSketchError):
            Sketch.from_bytes(b"ab")  # Less than 8 bytes for header

    def test_sketch_preserves_input_length(self):
        import numpy as np
        helper = (np.array([1, 2, 3], dtype=np.uint8),)
        sketch = Sketch(helper=helper, input_length=128)
        serialized = sketch.to_bytes()

        # First 4 bytes should be input_length in big-endian
        assert int.from_bytes(serialized[:4], "big") == 128


class TestFuzzyExtractorWrapper:
    """Test fuzzy extractor generate and reproduce operations."""

    def test_generate_returns_key_and_sketch(self, biometric_sample):
        fe = FuzzyExtractorWrapper()
        key, sketch = fe.generate(biometric_sample)

        assert isinstance(key, bytes)
        assert len(key) > 0
        assert isinstance(sketch, Sketch)

    def test_generate_empty_input_raises(self):
        fe = FuzzyExtractorWrapper()
        with pytest.raises(ValueError):
            fe.generate(b"")

    def test_reproduce_with_same_input(self, biometric_sample):
        """Reproduce should return same key for identical input."""
        fe = FuzzyExtractorWrapper()

        key1, sketch = fe.generate(biometric_sample)
        key2 = fe.reproduce(biometric_sample, sketch)

        assert key1 == key2

    def test_reproduce_with_similar_input(self, biometric_sample):
        """Reproduce should work with input within Hamming threshold."""
        fe = FuzzyExtractorWrapper(FuzzyExtractorParams(hamming_threshold=8))

        key1, sketch = fe.generate(biometric_sample)

        # Flip fewer bits than threshold
        noisy = flip_bits(biometric_sample, [0, 8, 16])  # 3 bits flipped
        key2 = fe.reproduce(noisy, sketch)

        assert key1 == key2

    def test_reproduce_fails_with_different_input(self, biometric_sample):
        """Reproduce should fail when input is completely different."""
        fe = FuzzyExtractorWrapper(FuzzyExtractorParams(hamming_threshold=8))

        _, sketch = fe.generate(biometric_sample)

        # Create a biometric that is maximally different (all bits flipped)
        different = bytes(b ^ 0xFF for b in biometric_sample)

        with pytest.raises(BiometricMismatchError):
            fe.reproduce(different, sketch)

    def test_reproduce_length_mismatch(self, biometric_sample):
        """Reproduce should fail if input length doesn't match sketch."""
        fe = FuzzyExtractorWrapper()

        _, sketch = fe.generate(biometric_sample)

        # Try with different length
        wrong_length = random_biometric(8)

        with pytest.raises(BiometricMismatchError, match="length mismatch"):
            fe.reproduce(wrong_length, sketch)


class TestModuleFunctions:
    """Test module-level convenience functions."""

    def test_generate_function(self, biometric_sample):
        key, sketch = generate(biometric_sample)

        assert isinstance(key, bytes)
        assert isinstance(sketch, Sketch)

    def test_reproduce_function(self, biometric_sample):
        key1, sketch = generate(biometric_sample)
        key2 = reproduce(biometric_sample, sketch)

        assert key1 == key2


class TestFuzzyExtractorSecurity:
    """Test security-related properties of the fuzzy extractor."""

    def test_different_biometrics_produce_different_keys(self):
        """Different biometric inputs should produce different keys."""
        bio1 = random_biometric()
        bio2 = random_biometric()
        fe = FuzzyExtractorWrapper()

        key1, _ = fe.generate(bio1)
        key2, _ = fe.generate(bio2)

        assert key1 != key2

    def test_key_has_sufficient_length(self, biometric_sample):
        """Generated keys should have sufficient length for security."""
        fe = FuzzyExtractorWrapper()
        key, _ = fe.generate(biometric_sample)

        # Key should be at least 16 bytes (128 bits)
        assert len(key) >= 16
