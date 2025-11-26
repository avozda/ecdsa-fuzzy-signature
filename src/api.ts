/**
 * Public API for biometric-based ECDSA signing.
 * 
 * This module exposes the main functions for enrollment, signing, and
 * verification. The "biometric" input is treated as an opaque Uint8Array
 * of fixed length. The caller is responsible for feature extraction,
 * normalization, and ensuring the biometric data is stable enough for
 * the fuzzy extractor to work.
 * 
 * Security assumptions:
 * - The biometric input must have sufficient min-entropy
 * - The biometric input should be preprocessed to minimize noise
 * - The sketch (helper data) is considered public but should be stored securely
 * - The verification key (public key) can be freely distributed
 */

import { fuzzyGen, fuzzyRep } from './fuzzy.js';
import { derivePrivateKey, getPublicKey, signMessage, verifySignature, isValidPublicKey } from './crypto.js';
import { EnrollmentResult, FuzzyExtractionError, FuzzyConfig, SignerConfig, BIOMETRIC_LENGTH } from './types.js';

/**
 * Enrolls a biometric input to generate a verification key and sketch.
 * 
 * This function performs the enrollment phase of biometric-based signing:
 * 1. Uses a fuzzy extractor to derive a stable key from the biometric
 * 2. Derives an ECDSA private key from the stable key
 * 3. Computes the corresponding public key (verification key)
 * 4. Returns the verification key and sketch for storage
 * 
 * The sketch must be stored and provided during signing. The verification
 * key can be shared publicly and used to verify signatures.
 * 
 * @param b - Biometric input as a fixed-length Uint8Array (32 bytes recommended)
 * @param config - Optional configuration for the fuzzy extractor
 * @returns Object containing verification key (vk) and sketch
 * 
 * @example
 * ```typescript
 * // Preprocess your biometric data into a fixed-length array
 * const biometric = preprocessBiometric(rawBiometricData);
 * 
 * // Enroll to get verification key and sketch
 * const { vk, sketch } = enroll(biometric);
 * 
 * // Store sketch securely, distribute vk for verification
 * ```
 */
export function enroll(b: Uint8Array, config?: SignerConfig): EnrollmentResult {
  validateBiometricInput(b);
  
  // Generate stable key and sketch using fuzzy extractor
  const { key, sketch } = fuzzyGen(b, config?.fuzzy);
  
  // Derive ECDSA private key from stable key
  const privateKey = derivePrivateKey(key);
  
  // Compute public key (verification key)
  const vk = getPublicKey(privateKey, true);
  
  return { vk, sketch };
}

/**
 * Signs a message using biometric authentication.
 * 
 * This function performs biometric-based signing:
 * 1. Uses the fuzzy extractor to reproduce the stable key from biometric and sketch
 * 2. Derives the same ECDSA private key as during enrollment
 * 3. Signs the message using ECDSA
 * 
 * The biometric input must be "close enough" to the enrollment biometric
 * for the fuzzy extractor to successfully reproduce the key. If the
 * biometric differs too much, this function throws FuzzyExtractionError.
 * 
 * @param b - Biometric input as a fixed-length Uint8Array
 * @param sketch - Sketch from enrollment (fuzzy extractor helper data)
 * @param message - Message to sign as Uint8Array
 * @param config - Optional configuration for the fuzzy extractor
 * @returns ECDSA signature as Uint8Array (64 bytes, compact format)
 * @throws FuzzyExtractionError if biometric reproduction fails
 * 
 * @example
 * ```typescript
 * const message = new TextEncoder().encode('Hello, World!');
 * 
 * try {
 *   const signature = sign(biometric, storedSketch, message);
 *   // Use signature for verification
 * } catch (error) {
 *   if (error instanceof FuzzyExtractionError) {
 *     console.error('Biometric mismatch - authentication failed');
 *   }
 * }
 * ```
 */
export function sign(
  b: Uint8Array,
  sketch: Uint8Array,
  message: Uint8Array,
  config?: SignerConfig
): Uint8Array {
  validateBiometricInput(b);
  
  // Reproduce stable key using fuzzy extractor
  const key = fuzzyRep(b, sketch);
  
  if (key === null) {
    throw new FuzzyExtractionError(
      'Failed to reproduce key from biometric input. ' +
      'The biometric may differ too much from enrollment.'
    );
  }
  
  // Derive ECDSA private key from stable key
  const privateKey = derivePrivateKey(key);
  
  // Sign the message
  return signMessage(message, privateKey);
}

/**
 * Verifies an ECDSA signature against a message and verification key.
 * 
 * This function verifies signatures without requiring biometric input.
 * It only needs the public verification key from enrollment.
 * 
 * @param vk - Verification key (public key) from enrollment
 * @param message - Original message that was signed
 * @param signature - Signature to verify
 * @returns true if signature is valid, false otherwise
 * 
 * @example
 * ```typescript
 * const message = new TextEncoder().encode('Hello, World!');
 * const isValid = verify(storedVk, message, signature);
 * 
 * if (isValid) {
 *   console.log('Signature verified successfully');
 * } else {
 *   console.error('Invalid signature');
 * }
 * ```
 */
export function verify(
  vk: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): boolean {
  // Validate public key format
  if (!isValidPublicKey(vk)) {
    return false;
  }
  
  return verifySignature(message, signature, vk);
}

/**
 * Validates that the biometric input has acceptable properties.
 * 
 * @param b - Biometric input to validate
 * @throws Error if input is invalid
 */
function validateBiometricInput(b: Uint8Array): void {
  if (!(b instanceof Uint8Array)) {
    throw new Error('Biometric input must be a Uint8Array');
  }
  
  if (b.length === 0) {
    throw new Error('Biometric input cannot be empty');
  }
  
  // Warn if input length differs from expected
  if (b.length !== BIOMETRIC_LENGTH) {
    // We allow different lengths but the default length is recommended
    // This is just a validation, not enforcement
  }
}

/**
 * Class-based wrapper for biometric signing operations.
 * 
 * Provides a stateful interface for enrollment and signing with
 * configurable parameters.
 * 
 * @example
 * ```typescript
 * const signer = new BiometricSigner();
 * 
 * // Enrollment phase
 * const { vk, sketch } = signer.enroll(biometric);
 * 
 * // Signing phase (can be on a different instance)
 * const signature = signer.sign(biometric, sketch, message);
 * 
 * // Verification (stateless, doesn't need biometric)
 * const isValid = BiometricSigner.verify(vk, message, signature);
 * ```
 */
export class BiometricSigner {
  private config: SignerConfig;
  
  /**
   * Creates a new BiometricSigner instance.
   * 
   * @param config - Optional configuration for the signer
   */
  constructor(config: SignerConfig = {}) {
    this.config = config;
  }
  
  /**
   * Enrolls a biometric input to generate verification key and sketch.
   * @see enroll
   */
  enroll(b: Uint8Array): EnrollmentResult {
    return enroll(b, this.config);
  }
  
  /**
   * Signs a message using biometric authentication.
   * @see sign
   */
  sign(b: Uint8Array, sketch: Uint8Array, message: Uint8Array): Uint8Array {
    return sign(b, sketch, message, this.config);
  }
  
  /**
   * Verifies an ECDSA signature against a message and verification key.
   * This is a static method as it doesn't require biometric input.
   * @see verify
   */
  static verify(vk: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
    return verify(vk, message, signature);
  }
}

