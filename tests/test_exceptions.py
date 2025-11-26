"""Tests for custom exceptions."""

import pytest

from biometricsig.exceptions import (
    BiometricSigError,
    BiometricMismatchError,
    InvalidSketchError,
    InvalidPublicKeyError,
    InvalidSignatureError,
    EnrollmentError,
)


class TestExceptionHierarchy:
    """Test that all exceptions inherit from BiometricSigError."""

    def test_biometric_mismatch_error_inheritance(self):
        assert issubclass(BiometricMismatchError, BiometricSigError)
        assert issubclass(BiometricMismatchError, Exception)

    def test_invalid_sketch_error_inheritance(self):
        assert issubclass(InvalidSketchError, BiometricSigError)

    def test_invalid_public_key_error_inheritance(self):
        assert issubclass(InvalidPublicKeyError, BiometricSigError)

    def test_invalid_signature_error_inheritance(self):
        assert issubclass(InvalidSignatureError, BiometricSigError)

    def test_enrollment_error_inheritance(self):
        assert issubclass(EnrollmentError, BiometricSigError)


class TestExceptionMessages:
    """Test exception default and custom messages."""

    def test_biometric_mismatch_default_message(self):
        exc = BiometricMismatchError()
        assert "unable to reconstruct" in str(exc).lower()

    def test_biometric_mismatch_custom_message(self):
        msg = "Custom mismatch message"
        exc = BiometricMismatchError(msg)
        assert str(exc) == msg
        assert exc.message == msg

    def test_invalid_sketch_default_message(self):
        exc = InvalidSketchError()
        assert "invalid" in str(exc).lower() or "corrupt" in str(exc).lower()

    def test_invalid_public_key_default_message(self):
        exc = InvalidPublicKeyError()
        assert "invalid" in str(exc).lower() and "public key" in str(exc).lower()

    def test_invalid_signature_default_message(self):
        exc = InvalidSignatureError()
        assert "invalid" in str(exc).lower() or "malformed" in str(exc).lower()


class TestExceptionRaising:
    """Test that exceptions can be raised and caught properly."""

    def test_catch_specific_exception(self):
        with pytest.raises(BiometricMismatchError):
            raise BiometricMismatchError("test")

    def test_catch_base_exception(self):
        """Verify we can catch specific exceptions with base class."""
        with pytest.raises(BiometricSigError):
            raise BiometricMismatchError("test")

    def test_exception_chaining(self):
        try:
            try:
                raise ValueError("original")
            except ValueError as e:
                raise BiometricMismatchError("wrapper") from e
        except BiometricMismatchError as e:
            assert e.__cause__ is not None
            assert isinstance(e.__cause__, ValueError)

