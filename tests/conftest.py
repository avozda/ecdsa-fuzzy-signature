"""Pytest configuration and shared fixtures."""

import os
import pytest

# Use smaller biometric size for faster tests
DEFAULT_TEST_BIOMETRIC_SIZE = 16


@pytest.fixture(scope="module")
def biometric_sample():
    """Generate a random biometric sample for testing."""
    return os.urandom(DEFAULT_TEST_BIOMETRIC_SIZE)


@pytest.fixture(scope="module")
def enrolled_data(biometric_sample):
    """
    Create an enrollment that can be reused across tests in a module.

    This fixture is module-scoped to avoid repeating the expensive
    fuzzy extractor generation for each test.
    """
    from biometricsig import enroll
    vk, sketch = enroll(biometric_sample)
    return {
        "biometric": biometric_sample,
        "vk": vk,
        "sketch": sketch,
    }

