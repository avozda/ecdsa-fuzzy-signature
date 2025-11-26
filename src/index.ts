/**
 * ecdsa-fuzzy-signature
 *
 * A TypeScript library for biometric-based signing using fuzzy extractors and ECDSA.
 *
 * This library provides a simple API to:
 * - Enroll biometric data to generate a verification key and sketch
 * - Sign messages using biometric authentication
 * - Verify signatures using the public verification key
 *
 * The library treats "biometric" as an opaque Uint8Array. The caller is responsible
 * for feature extraction, normalization, and making the biometric data stable enough.
 *
 * @example
 * ```typescript
 * import { enroll, sign, verify } from 'ecdsa-fuzzy-signature';
 *
 * // Enrollment
 * const biometric = new Uint8Array(32); // Your preprocessed biometric
 * const { vk, sketch } = enroll(biometric);
 *
 * // Signing
 * const message = new TextEncoder().encode('Hello, World!');
 * const signature = sign(biometric, sketch, message);
 *
 * // Verification
 * const isValid = verify(vk, message, signature);
 * ```
 *
 * @packageDocumentation
 */

// Main API functions
export { enroll, sign, verify, BiometricSigner } from "./api.js";

// Fuzzy extractor functions (for advanced use)
export { fuzzyGen, fuzzyRep, computeSimilarity } from "./fuzzy.js";

// Crypto utilities (for advanced use)
export {
  derivePrivateKey,
  getPublicKey,
  signMessage,
  verifySignature,
  isValidPrivateKey,
  isValidPublicKey,
} from "./crypto.js";

// Types and errors
export type {
  EnrollmentResult,
  FuzzyGenResult,
  FuzzyConfig,
  SignerConfig,
} from "./types.js";

export {
  FuzzyExtractionError,
  SignatureVerificationError,
  BIOMETRIC_LENGTH,
  KEY_LENGTH,
} from "./types.js";
