# ecdsa-fuzzy-signature

A TypeScript library for biometric-based digital signatures using fuzzy extractors and ECDSA.

This library provides a simple API to derive ECDSA signing keys from noisy biometric data, enabling biometric authentication for digital signatures without storing the biometric template directly.

## Overview

The library treats "biometric" as an opaque `Uint8Array` of fixed length. The caller is responsible for:
- Feature extraction from raw biometric data (fingerprint, face, iris, etc.)
- Normalization and quantization to produce a stable `Uint8Array`
- Ensuring sufficient entropy in the biometric representation

The library handles:
- Fuzzy extraction to derive stable cryptographic keys from noisy inputs
- ECDSA key derivation and signing on the secp256k1 curve
- Signature verification using standard ECDSA

## Literature and Background

### Fuzzy Extractors

Fuzzy extractors are cryptographic primitives that derive strong, reproducible keys from noisy data. They were formalized by Dodis et al. in ["Fuzzy Extractors: How to Generate Strong Keys from Biometrics and Other Noisy Data"](https://eprint.iacr.org/2003/235).

A fuzzy extractor consists of two procedures:
- **Gen(b)**: Takes a biometric input `b` and outputs a stable key `K` and helper data (sketch) `P`
- **Rep(b', P)**: Given a noisy version `b'` close to the original `b` and the sketch `P`, reproduces the same key `K`

This library implements a code-and-hash construction using repetition codes for error correction and HKDF for key derivation.

### Secure Sketches

A secure sketch allows recovering the original biometric from a noisy reading without revealing the biometric itself. The sketch leaks some information about the biometric (bounded by the error tolerance), so the biometric must have sufficient min-entropy.

### ECDSA Signatures

The library uses ECDSA (Elliptic Curve Digital Signature Algorithm) on the secp256k1 curve for digital signatures. Signatures follow RFC 6979 for deterministic nonce generation, ensuring:
- Same message + key always produces the same signature
- No random number generator vulnerabilities

## Software Requirements

- **Node.js**: ≥ 18.0.0
- **TypeScript**: ≥ 5.0.0 (for development)

### Dependencies

- `@noble/curves` - Audited, minimal ECDSA implementation
- `@noble/hashes` - Audited, minimal hash functions (SHA-256, HKDF)

## Installation

### As a Git Submodule

```bash
# Add as submodule
git submodule add https://github.com/your-username/ecdsa-fuzzy-signature.git lib/ecdsa-fuzzy-signature

# Install dependencies
cd lib/ecdsa-fuzzy-signature
npm install

# Build the library
npm run build
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/your-username/ecdsa-fuzzy-signature.git
cd ecdsa-fuzzy-signature

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test
```

## Usage

### Basic Example

```typescript
import { enroll, sign, verify } from 'ecdsa-fuzzy-signature';

// 1. Enrollment: Generate verification key and sketch from biometric
const biometric = new Uint8Array(32); // Your preprocessed biometric data
const { vk, sketch } = enroll(biometric);

// Store `sketch` securely (needed for signing)
// Distribute `vk` publicly (for verification)

// 2. Signing: Create signature using biometric and sketch
const message = new TextEncoder().encode('Hello, World!');
const signature = sign(biometric, sketch, message);

// 3. Verification: Verify signature using public key only
const isValid = verify(vk, message, signature);
console.log('Signature valid:', isValid); // true
```

### Handling Biometric Mismatch

```typescript
import { sign, FuzzyExtractionError } from 'ecdsa-fuzzy-signature';

try {
  const signature = sign(biometric, sketch, message);
} catch (error) {
  if (error instanceof FuzzyExtractionError) {
    console.error('Biometric authentication failed');
    // Handle authentication failure
  }
}
```

### Class-Based API

```typescript
import { BiometricSigner } from 'ecdsa-fuzzy-signature';

const signer = new BiometricSigner();

// Enrollment
const { vk, sketch } = signer.enroll(biometric);

// Signing
const signature = signer.sign(biometric, sketch, message);

// Verification (static method - no biometric needed)
const isValid = BiometricSigner.verify(vk, message, signature);
```

### Preparing Biometric Data

The library expects a fixed-length `Uint8Array`. Here's an example of converting a 128-dimensional float embedding (common in face recognition) to the expected format:

```typescript
/**
 * Convert a float embedding to Uint8Array for the fuzzy extractor.
 * This is an example - adapt to your specific biometric system.
 */
function embeddingToBytes(embedding: Float32Array): Uint8Array {
  // Option 1: Direct byte conversion (32 bytes from 8 floats)
  const buffer = new ArrayBuffer(32);
  const view = new DataView(buffer);
  for (let i = 0; i < 8 && i < embedding.length; i++) {
    view.setFloat32(i * 4, embedding[i], true);
  }
  return new Uint8Array(buffer);
  
  // Option 2: Quantize to bytes (more compact)
  // const quantized = new Uint8Array(32);
  // for (let i = 0; i < 32 && i < embedding.length; i++) {
  //   // Map [-1, 1] to [0, 255]
  //   quantized[i] = Math.round((embedding[i] + 1) * 127.5);
  // }
  // return quantized;
}

// Usage
const faceEmbedding = getFaceEmbedding(image); // From your face recognition model
const biometric = embeddingToBytes(faceEmbedding);
const { vk, sketch } = enroll(biometric);
```

## Architecture

```
src/
├── index.ts     # Main exports
├── api.ts       # Public API: enroll(), sign(), verify()
├── fuzzy.ts     # Fuzzy extractor: Gen(), Rep()
├── crypto.ts    # ECDSA utilities: key derivation, signing
└── types.ts     # TypeScript type definitions

tests/
├── api.test.ts    # Integration tests
├── crypto.test.ts # ECDSA unit tests
└── fuzzy.test.ts  # Fuzzy extractor unit tests
```

### Data Flow

```
Enrollment:
  biometric (Uint8Array)
      │
      ▼
  ┌──────────────┐
  │ Fuzzy Gen()  │ ──► sketch (helper data)
  └──────────────┘
      │
      ▼ key
  ┌──────────────┐
  │    HKDF      │
  └──────────────┘
      │
      ▼ privateKey
  ┌──────────────┐
  │ ECDSA getPub │ ──► vk (verification key)
  └──────────────┘

Signing:
  biometric + sketch
      │
      ▼
  ┌──────────────┐
  │ Fuzzy Rep()  │ ──► key (or error)
  └──────────────┘
      │
      ▼ key
  ┌──────────────┐
  │    HKDF      │
  └──────────────┘
      │
      ▼ privateKey
  ┌──────────────┐
  │ ECDSA sign   │ ──► signature
  └──────────────┘

Verification:
  vk + message + signature
      │
      ▼
  ┌──────────────┐
  │ ECDSA verify │ ──► boolean
  └──────────────┘
```

### Module Descriptions

- **api.ts**: High-level functions that compose the fuzzy extractor and ECDSA operations. Handles input validation and error translation.

- **fuzzy.ts**: Implements the fuzzy extractor using a code-and-hash construction with repetition codes. Supports configurable error tolerance.

- **crypto.ts**: Wraps `@noble/curves` for secp256k1 operations. Handles key derivation from raw entropy using HKDF.

- **types.ts**: TypeScript interfaces and error classes. Defines `EnrollmentResult`, `FuzzyConfig`, and custom errors.

## Security Considerations

1. **Biometric Entropy**: The security of the derived keys depends on the min-entropy of the biometric input. Ensure your biometric system produces high-entropy representations.

2. **Sketch Storage**: The sketch reveals some information about the biometric (bounded by error tolerance). Store it securely and consider it sensitive.

3. **Error Tolerance Trade-off**: Higher error tolerance (more bit flips allowed) provides better usability but reduces security. The default parameters balance these concerns.

4. **No Template Storage**: The actual biometric is never stored. Only the sketch (helper data) is needed, which cannot be used to reconstruct the original biometric.

5. **Constant-Time Operations**: The underlying `@noble/curves` library uses constant-time implementations to resist timing attacks.

## API Reference

### `enroll(b: Uint8Array, config?: SignerConfig): EnrollmentResult`

Enrolls a biometric to generate verification key and sketch.

- **Parameters**:
  - `b`: Biometric input (recommended: 32 bytes)
  - `config`: Optional configuration
- **Returns**: `{ vk: Uint8Array, sketch: Uint8Array }`

### `sign(b: Uint8Array, sketch: Uint8Array, message: Uint8Array): Uint8Array`

Signs a message using biometric authentication.

- **Parameters**:
  - `b`: Biometric input
  - `sketch`: Sketch from enrollment
  - `message`: Message to sign
- **Returns**: Signature (64 bytes, compact format)
- **Throws**: `FuzzyExtractionError` if biometric mismatch

### `verify(vk: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean`

Verifies an ECDSA signature.

- **Parameters**:
  - `vk`: Verification key from enrollment
  - `message`: Original message
  - `signature`: Signature to verify
- **Returns**: `true` if valid, `false` otherwise

## License

GPL-3.0

