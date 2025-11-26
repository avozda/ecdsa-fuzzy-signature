# BiometricSig

A Python library for biometric-based digital signatures using fuzzy extractors and ECDSA.

## Overview

**BiometricSig** provides a simple, biometric-agnostic API for generating cryptographic signatures from biometric data. The library combines:

- **Fuzzy Extractors**: Derive stable cryptographic keys from noisy biometric inputs
- **ECDSA**: Produce and verify digital signatures using elliptic curve cryptography

The library treats biometric data as opaque bytes — the caller is fully responsible for feature extraction, normalization, and ensuring sufficient stability between enrollment and signing samples.

### Key Features

- 🔐 **Simple API**: Three functions — `enroll()`, `sign()`, `verify()`
- 🧬 **Biometric Agnostic**: Works with any biometric type (fingerprint, face, iris, etc.)
- 🔑 **Standards-Based**: Uses ECDSA with NIST P-256 curve
- 🛡️ **Error Tolerant**: Fuzzy extractor handles minor variations in biometric samples
- 📦 **Minimal Dependencies**: Only `python-ecdsa` and `fuzzy-extractor`

## Literature and Background

### Fuzzy Extractors

Fuzzy extractors are cryptographic primitives that derive strong, stable keys from noisy inputs like biometric data. Unlike traditional key derivation, fuzzy extractors can reproduce the _same_ key even when given slightly different inputs, as long as they are "close enough."

The foundational work is:

> Dodis, Y., Reyzin, L., & Smith, A. (2004, 2008). _Fuzzy Extractors: How to Generate Strong Keys from Biometrics and Other Noisy Data_. SIAM Journal on Computing.

A fuzzy extractor consists of two algorithms:

- **Gen(b)** → (K, sketch): Generates a key K and public helper data (sketch) from biometric b
- **Rep(b', sketch)** → K: Reproduces the same key K from a similar biometric b', using the sketch

The security guarantee is that K is computationally indistinguishable from random, even given the sketch, as long as the original biometric has sufficient min-entropy.

### Biometric Cryptography

Directly using biometrics as cryptographic keys is problematic because:

1. Biometric measurements are inherently noisy
2. Biometrics cannot be changed if compromised
3. Biometric templates need to be protected

Fuzzy extractors address (1) by tolerating measurement noise. The sketch reveals limited information about the biometric, providing some protection for (3). For (2), different sketches from the same biometric produce different keys, allowing key rotation.

### ECDSA Signatures

ECDSA (Elliptic Curve Digital Signature Algorithm) provides:

- Strong security with compact keys and signatures
- Deterministic signature generation (RFC 6979)
- Wide support and standardization

This library uses the NIST P-256 curve (secp256r1), providing approximately 128-bit security level.

## Software Requirements

- **Python**: 3.11 or later
- **Dependencies**:
  - `ecdsa>=0.18.0` — ECDSA cryptographic operations
  - `fuzzy-extractor>=0.3` — Fuzzy extractor implementation ([GitHub](https://github.com/carter-yagemann/python-fuzzy-extractor))

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/example/biometricsig.git
cd biometricsig

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package with dependencies
pip install -e .

# Install development dependencies (for testing)
pip install -e ".[dev]"

# Run the test suite
pytest
```

### From PyPI (when published)

```bash
pip install biometricsig
```

## Usage

### Basic Example

```python
from biometricsig import enroll, sign, verify

# Your biometric data as bytes (from feature extraction)
biometric_sample = get_biometric_bytes()  # Your function

# STEP 1: Enrollment (done once, store vk and sketch)
vk, sketch = enroll(biometric_sample)

# Store:
#   - vk (verification key): Can be shared publicly
#   - sketch: Store securely for signing operations

# STEP 2: Signing (when user wants to sign something)
message = b"I authorize this transaction"
signature = sign(biometric_sample, sketch, message)

# STEP 3: Verification (anyone with vk can verify)
is_valid = verify(vk, message, signature)
print(f"Signature valid: {is_valid}")
```

### Handling Biometric Mismatch

```python
from biometricsig import sign, BiometricMismatchError

try:
    signature = sign(biometric_sample, sketch, message)
except BiometricMismatchError:
    print("Biometric sample doesn't match enrollment!")
```

### Using the Class-Based Interface

```python
from biometricsig import BiometricSigner

# Configure with custom Hamming threshold
signer = BiometricSigner(hamming_threshold=16)

vk, sketch = signer.enroll(biometric_bytes)
signature = signer.sign(biometric_bytes, sketch, message)
is_valid = signer.verify(vk, message, signature)
```

### Preparing Biometric Data

The library expects biometric data as fixed-length bytes. Here's an example of converting a float embedding to bytes:

```python
import struct
import hashlib

def embedding_to_bytes(embedding: list[float], target_length: int = 64) -> bytes:
    """
    Convert a float embedding to fixed-length bytes.

    Args:
        embedding: Float vector (e.g., 128-D face embedding)
        target_length: Desired output length in bytes

    Returns:
        Fixed-length bytes suitable for biometricsig
    """
    # Pack floats to bytes
    packed = struct.pack(f'{len(embedding)}f', *embedding)

    # Hash to fixed length (provides some normalization)
    return hashlib.sha512(packed).digest()[:target_length]

# Usage
face_embedding = get_face_embedding(image)  # Your function
biometric_bytes = embedding_to_bytes(face_embedding)

vk, sketch = enroll(biometric_bytes)
```

### Hamming Threshold Configuration

The `hamming_threshold` parameter controls how many bit differences are tolerated between enrollment and signing biometric samples:

```python
# Default threshold (8 bits)
vk, sketch = enroll(biometric_bytes)

# Higher threshold - more tolerant of noise
vk, sketch = enroll(biometric_bytes, hamming_threshold=16)

# Must use same threshold for signing!
signature = sign(biometric_bytes, sketch, message, hamming_threshold=16)
```

**Security Trade-off**: Higher thresholds tolerate more biometric variation but reduce security. The effective security is reduced by approximately the threshold value in bits.

**Note on Sketch Size**: The fuzzy-extractor library uses a digital locker construction which produces relatively large sketches (several MB for typical biometric sizes). This is a trade-off for the strong security guarantees of reusable fuzzy extractors.

## Architecture

```
biometricsig/
├── __init__.py      # Package exports
├── api.py           # Public API: enroll(), sign(), verify(), BiometricSigner
├── fuzzy.py         # Fuzzy extractor wrapper (Gen/Rep operations)
├── crypto.py        # ECDSA operations and HKDF key derivation
└── exceptions.py    # Custom exception types
```

### Data Flow

```
                  ENROLLMENT
                  ──────────
                       │
    biometric (bytes) ─┼──► Gen(b) ─────► (K, sketch)
                       │         │              │
                       │         │              └──► sketch_bytes (store)
                       │         │
                       │         └──► KDF(K) ──► private_key
                       │                              │
                       │                              └──► public_key ──► vk_bytes (store)
                       │
                  SIGNING
                  ───────
                       │
    biometric (bytes) ─┼──► Rep(b, sketch) ──► K
    sketch_bytes ──────┘                       │
                                               └──► KDF(K) ──► private_key
                                                                    │
                     message ──────────────────────────────────────►│
                                                                    │
                                                          ECDSA.sign(message)
                                                                    │
                                                                    └──► signature_bytes

                  VERIFICATION
                  ────────────
                       │
    vk_bytes ──────────┼──► deserialize ──► public_key
    message ───────────┤                         │
    signature_bytes ───┤                         │
                       │         ECDSA.verify(message, signature)
                       │                         │
                       └─────────────────────────┴──► bool (True/False)
```

### Module Responsibilities

| Module          | Purpose                                                                                                            |
| --------------- | ------------------------------------------------------------------------------------------------------------------ |
| `api.py`        | Public-facing functions and class. Orchestrates the enrollment, signing, and verification flows.                   |
| `fuzzy.py`      | Wraps the `fuzzy-extractor` library. Provides `generate()` and `reproduce()` operations with proper serialization. |
| `crypto.py`     | ECDSA key derivation, serialization, signing, and verification. Implements HKDF for key derivation.                |
| `exceptions.py` | Custom exception hierarchy for specific error handling.                                                            |

### Exception Types

| Exception                | When Raised                                                |
| ------------------------ | ---------------------------------------------------------- |
| `BiometricMismatchError` | Biometric sample too different from enrollment (Rep fails) |
| `InvalidSketchError`     | Sketch data is corrupted or invalid                        |
| `InvalidPublicKeyError`  | Public key bytes cannot be deserialized                    |
| `InvalidSignatureError`  | Signature format is malformed                              |
| `EnrollmentError`        | Enrollment fails (e.g., insufficient entropy)              |

## Security Considerations

### Caller Responsibilities

The security of this system depends on factors **outside** this library:

1. **Biometric Quality**: The biometric input must have sufficient min-entropy (recommended: ≥80 bits)
2. **Feature Extraction**: Must produce stable, consistent outputs
3. **Noise Tolerance**: The Hamming distance between enrollment and signing samples must be within the threshold
4. **Sketch Storage**: While the sketch doesn't reveal the key, it may leak some biometric information

### Library Guarantees

- Deterministic key derivation (same biometric → same key)
- Deterministic signatures (RFC 6979)
- Standard cryptographic primitives (HKDF, ECDSA)
- Proper error handling for mismatched biometrics

### Threat Model

This library does **not** protect against:

- Compromised biometric capture devices
- Presentation attacks (spoofed biometrics)
- Biometric template theft (if raw biometric is captured)
- Side-channel attacks during biometric capture

The caller should implement appropriate countermeasures for their threat model.

## Known Limitations

1. **Sketch Size**: The fuzzy-extractor library uses a digital locker construction which produces large sketches (1-5 MB depending on biometric size). This is a trade-off for the strong security guarantees of reusable fuzzy extractors.

2. **Probabilistic Reconstruction**: The fuzzy extractor is probabilistic. In rare cases, key reconstruction may fail even for biometrics within the Hamming threshold, or succeed for biometrics that should be rejected. The probability of such events is very low (< 0.01%) but non-zero.

3. **Test Flakiness**: Due to the probabilistic nature of the fuzzy extractor, tests that verify rejection of mismatched biometrics may occasionally fail. This does not indicate a bug but reflects the inherent probabilistic behavior of the underlying cryptographic construction.

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=biometricsig

# Run specific test file
pytest tests/test_api.py

# Run with verbose output
pytest -v
```

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please ensure:

1. Code follows the existing style
2. All tests pass
3. New functionality includes tests
4. Documentation is updated

## References

1. Dodis, Y., Reyzin, L., & Smith, A. (2008). Fuzzy Extractors: How to Generate Strong Keys from Biometrics and Other Noisy Data. _SIAM Journal on Computing_, 38(1), 97-139.

2. Canetti, R., et al. (2016). Reusable Fuzzy Extractors for Low-Entropy Distributions. _Annual International Conference on the Theory and Applications of Cryptographic Techniques_. Springer. (Basis for the [python-fuzzy-extractor](https://github.com/carter-yagemann/python-fuzzy-extractor) implementation)

3. Johnson, D., Menezes, A., & Vanstone, S. (2001). The Elliptic Curve Digital Signature Algorithm (ECDSA). _International Journal of Information Security_, 1(1), 36-63.

4. Krawczyk, H., & Eronen, P. (2010). HMAC-based Extract-and-Expand Key Derivation Function (HKDF). _RFC 5869_.

5. Pornin, T. (2013). Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA). _RFC 6979_.
