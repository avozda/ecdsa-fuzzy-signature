"""
Compatibility shim for fuzzy-extractor library.

The fuzzy-extractor library (https://github.com/carter-yagemann/python-fuzzy-extractor)
has two compatibility issues with modern Python:

1. It depends on fastpbkdf2, which has C extension compatibility issues with
   Python 3.13+. We provide a drop-in replacement using hashlib.pbkdf2_hmac.

2. It uses np.fromstring() which was removed in NumPy 2.0+. We patch numpy
   to redirect fromstring to frombuffer.
"""

import hashlib
import sys


def pbkdf2_hmac(hash_name: str, password: bytes, salt: bytes, iterations: int, dklen: int | None = None) -> bytes:
    """
    PBKDF2-HMAC key derivation using hashlib.

    This is a drop-in replacement for fastpbkdf2.pbkdf2_hmac.

    Args:
        hash_name: Hash algorithm name (e.g., 'sha256', 'sha512')
        password: Password/input bytes
        salt: Salt bytes
        iterations: Number of iterations
        dklen: Derived key length (optional)

    Returns:
        Derived key bytes
    """
    return hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)


def _install_fastpbkdf2_shim():
    """
    Install this module as a replacement for fastpbkdf2.

    This allows the fuzzy_extractor library to import fastpbkdf2
    and get our hashlib-based implementation instead.
    """
    import types

    # Create a fake fastpbkdf2 module
    fake_module = types.ModuleType("fastpbkdf2")
    fake_module.pbkdf2_hmac = pbkdf2_hmac

    # Insert into sys.modules so imports find it
    sys.modules["fastpbkdf2"] = fake_module

    # Also need to handle the _fastpbkdf2 submodule that the real package tries to import
    fake_submodule = types.ModuleType("fastpbkdf2._fastpbkdf2")
    sys.modules["fastpbkdf2._fastpbkdf2"] = fake_submodule


def _patch_numpy_fromstring():
    """
    Patch numpy.fromstring to use frombuffer.

    The fuzzy-extractor library uses np.fromstring() with binary data,
    which was removed in NumPy 2.0. We patch it to use np.frombuffer()
    which provides the same functionality for binary data.
    """
    import numpy as np

    if not hasattr(np, '_original_fromstring'):
        # Save original if it exists (for older numpy versions)
        if hasattr(np, 'fromstring'):
            np._original_fromstring = np.fromstring

        # Create a wrapper that uses frombuffer for binary mode
        def patched_fromstring(string, dtype=float, count=-1, *, sep='', like=None):
            if sep == '' or sep is None:
                # Binary mode - use frombuffer instead
                if count == -1:
                    return np.frombuffer(string, dtype=dtype)
                else:
                    return np.frombuffer(string, dtype=dtype, count=count)
            else:
                # Text mode with separator - this should still work
                # in older numpy or raise an appropriate error
                if hasattr(np, '_original_fromstring'):
                    return np._original_fromstring(string, dtype=dtype, count=count, sep=sep)
                else:
                    raise ValueError(
                        "np.fromstring with sep parameter is not supported. "
                        "Use np.fromiter or parse the string differently."
                    )

        np.fromstring = patched_fromstring


# Install the shims when this module is imported
_install_fastpbkdf2_shim()
_patch_numpy_fromstring()

