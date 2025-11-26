"""
Fuzzy extractor wrapper for deriving stable keys from noisy biometric data.

This module provides a wrapper around the fuzzy-extractor library
(https://github.com/carter-yagemann/python-fuzzy-extractor),
implementing the Gen (generation) and Rep (reproduction) operations
needed for biometric-based cryptography.

A fuzzy extractor allows deriving a stable cryptographic key from
noisy biometric inputs. If two biometric samples are "close enough"
(within the error-correction threshold in Hamming distance), the
same key will be reproduced.

Security Note:
    The security of this scheme depends critically on:
    1. The min-entropy of the biometric input
    2. The stability/repeatability of the biometric feature extraction
    3. Proper parameterization of the fuzzy extractor (error threshold)

References:
    Dodis et al., "Fuzzy Extractors: How to Generate Strong Keys from
    Biometrics and Other Noisy Data" (2004, 2008)

    Canetti et al., "Reusable fuzzy extractors for low-entropy distributions"
    (2016) - basis for the python-fuzzy-extractor implementation
"""

from dataclasses import dataclass
from typing import Tuple

# Install the fastpbkdf2 shim before importing fuzzy_extractor
# This provides compatibility with Python 3.13+ where fastpbkdf2's
# C extension doesn't build properly
from . import _fastpbkdf2_shim  # noqa: F401

from fuzzy_extractor import FuzzyExtractor

from .exceptions import BiometricMismatchError, InvalidSketchError


# Default parameters for the fuzzy extractor
# These should be tuned based on the expected biometric noise characteristics
DEFAULT_HAMMING_THRESHOLD = 8  # Maximum Hamming distance (bits) for successful reconstruction


@dataclass(frozen=True)
class FuzzyExtractorParams:
    """
    Parameters for the fuzzy extractor.

    Attributes:
        hamming_threshold: Maximum number of bit flips allowed between enrollment
            and signing biometric samples for successful key reconstruction.
            Higher values tolerate more noise but reduce security.

    Security Note:
        The hamming_threshold directly impacts security. A threshold of t bits
        means an attacker who can guess t bits of the biometric has an advantage.
        The effective security is reduced by approximately t bits.
    """

    hamming_threshold: int = DEFAULT_HAMMING_THRESHOLD

    def __post_init__(self) -> None:
        if self.hamming_threshold < 0:
            raise ValueError("hamming_threshold must be non-negative")


@dataclass
class Sketch:
    """
    Helper data produced during enrollment for key reconstruction.

    The sketch contains the information needed by the fuzzy extractor's
    Rep operation to reconstruct the key from a noisy biometric sample.

    The helper data from the fuzzy-extractor library is a tuple of numpy
    arrays. This class handles serialization to/from bytes.

    Security Note:
        The sketch is considered public information and does not leak
        the key (information-theoretically, given sufficient min-entropy
        in the biometric). However, it may leak some information about
        the biometric itself.
    """

    helper: tuple  # The raw helper tuple from fuzzy_extractor
    input_length: int  # Length of the original biometric input in bytes

    def to_bytes(self) -> bytes:
        """
        Serialize the sketch to bytes for storage.

        Format:
            [4 bytes: input_length (big-endian)]
            [4 bytes: num_arrays (big-endian)]
            For each array:
                [4 bytes: array_size (big-endian)]
                [N bytes: array data as bytes]
        """
        import numpy as np

        parts = [self.input_length.to_bytes(4, "big")]
        parts.append(len(self.helper).to_bytes(4, "big"))

        for arr in self.helper:
            # Convert numpy array to bytes
            arr_bytes = arr.tobytes()
            # Store shape info for reconstruction
            shape_str = ",".join(str(d) for d in arr.shape)
            shape_bytes = shape_str.encode("utf-8")
            dtype_str = str(arr.dtype)
            dtype_bytes = dtype_str.encode("utf-8")

            # Format: [shape_len][shape][dtype_len][dtype][data_len][data]
            parts.append(len(shape_bytes).to_bytes(2, "big"))
            parts.append(shape_bytes)
            parts.append(len(dtype_bytes).to_bytes(2, "big"))
            parts.append(dtype_bytes)
            parts.append(len(arr_bytes).to_bytes(4, "big"))
            parts.append(arr_bytes)

        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Sketch":
        """Deserialize a sketch from bytes."""
        import numpy as np

        if len(data) < 8:
            raise InvalidSketchError("Sketch data too short")

        offset = 0
        input_length = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4

        num_arrays = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4

        arrays = []
        for _ in range(num_arrays):
            try:
                # Read shape
                shape_len = int.from_bytes(data[offset:offset + 2], "big")
                offset += 2
                shape_str = data[offset:offset + shape_len].decode("utf-8")
                offset += shape_len
                shape = tuple(int(d) for d in shape_str.split(",") if d)

                # Read dtype
                dtype_len = int.from_bytes(data[offset:offset + 2], "big")
                offset += 2
                dtype_str = data[offset:offset + dtype_len].decode("utf-8")
                offset += dtype_len
                dtype = np.dtype(dtype_str)

                # Read array data
                arr_len = int.from_bytes(data[offset:offset + 4], "big")
                offset += 4
                arr_bytes = data[offset:offset + arr_len]
                offset += arr_len

                # Reconstruct array
                arr = np.frombuffer(arr_bytes, dtype=dtype).reshape(shape)
                arrays.append(arr)
            except Exception as e:
                raise InvalidSketchError(f"Failed to deserialize sketch: {e}") from e

        return cls(helper=tuple(arrays), input_length=input_length)


class FuzzyExtractorWrapper:
    """
    Wrapper around the fuzzy extractor providing Gen and Rep operations.

    This class encapsulates the fuzzy extractor logic from the
    python-fuzzy-extractor library and provides a clean interface
    for the biometric signing library.

    The underlying implementation uses a digital locker construction
    based on the work by Canetti et al. on reusable fuzzy extractors.

    Example:
        >>> fe = FuzzyExtractorWrapper()
        >>> key, sketch = fe.generate(biometric_bytes)
        >>> # Later, with a similar biometric sample:
        >>> recovered_key = fe.reproduce(similar_biometric_bytes, sketch)
        >>> assert key == recovered_key  # If samples are close enough
    """

    def __init__(self, params: FuzzyExtractorParams | None = None):
        """
        Initialize the fuzzy extractor wrapper.

        Args:
            params: Optional parameters for the fuzzy extractor.
                   Uses defaults if not provided.
        """
        self.params = params or FuzzyExtractorParams()

    def _create_extractor(self, input_length_bytes: int) -> FuzzyExtractor:
        """
        Create a FuzzyExtractor instance for the given input size.

        The fuzzy-extractor library requires knowing the input size
        in bytes at construction time.
        """
        return FuzzyExtractor(
            input_length_bytes,
            self.params.hamming_threshold,
        )

    def generate(self, biometric: bytes) -> Tuple[bytes, Sketch]:
        """
        Generate a key and sketch from a biometric sample (Gen operation).

        This is called during enrollment to produce a stable key and
        helper sketch that will be used for future signing operations.

        Args:
            biometric: The biometric sample as bytes. Must be of fixed length
                      appropriate for the biometric type.

        Returns:
            A tuple of (key, sketch) where:
                - key: The derived cryptographic key (bytes)
                - sketch: Helper data for reconstruction (Sketch object)

        Raises:
            ValueError: If the biometric input is empty.
        """
        if not biometric:
            raise ValueError("Biometric input cannot be empty")

        extractor = self._create_extractor(len(biometric))

        # Generate key and helper data
        # The library's generate() returns (key, helper)
        # where helper is a tuple of numpy arrays
        key, helper = extractor.generate(biometric)

        # The key from fuzzy_extractor is already bytes
        # Wrap helper in our Sketch class for serialization
        sketch = Sketch(helper=helper, input_length=len(biometric))

        return key, sketch

    def reproduce(self, biometric: bytes, sketch: Sketch) -> bytes:
        """
        Reproduce the key from a biometric sample and sketch (Rep operation).

        This is called during signing to recover the same key that was
        generated during enrollment, provided the biometric samples are
        close enough (within the Hamming distance threshold).

        Args:
            biometric: The biometric sample as bytes. Should be similar
                      to the enrollment sample.
            sketch: The sketch produced during enrollment.

        Returns:
            The reproduced key (bytes), identical to the enrollment key
            if the biometric samples are within the error threshold.

        Raises:
            BiometricMismatchError: If the biometric sample is too different
                from the enrollment sample (exceeds Hamming threshold).
            InvalidSketchError: If the sketch is invalid.
        """
        if len(biometric) != sketch.input_length:
            raise BiometricMismatchError(
                f"Biometric length mismatch: expected {sketch.input_length} bytes, "
                f"got {len(biometric)} bytes"
            )

        extractor = self._create_extractor(len(biometric))

        try:
            key = extractor.reproduce(biometric, sketch.helper)
        except Exception as e:
            # The fuzzy_extractor library raises various exceptions on failure
            raise BiometricMismatchError(
                f"Failed to reconstruct key from biometric: {e}"
            ) from e

        if key is None:
            raise BiometricMismatchError(
                "Biometric sample differs too much from enrollment sample"
            )

        return key


# Module-level convenience functions using default parameters


def generate(biometric: bytes, params: FuzzyExtractorParams | None = None) -> Tuple[bytes, Sketch]:
    """
    Generate a key and sketch from a biometric sample.

    Convenience function using default or specified parameters.

    Args:
        biometric: The biometric sample as bytes.
        params: Optional fuzzy extractor parameters.

    Returns:
        Tuple of (key, sketch).
    """
    wrapper = FuzzyExtractorWrapper(params)
    return wrapper.generate(biometric)


def reproduce(
    biometric: bytes, sketch: Sketch, params: FuzzyExtractorParams | None = None
) -> bytes:
    """
    Reproduce a key from a biometric sample and sketch.

    Convenience function using default or specified parameters.

    Args:
        biometric: The biometric sample as bytes.
        sketch: The sketch from enrollment.
        params: Optional fuzzy extractor parameters (must match enrollment).

    Returns:
        The reproduced key.

    Raises:
        BiometricMismatchError: If reconstruction fails.
    """
    wrapper = FuzzyExtractorWrapper(params)
    return wrapper.reproduce(biometric, sketch)
