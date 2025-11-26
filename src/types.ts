/**
 * Result of the fuzzy extractor Gen operation.
 * Contains a stable cryptographic key derived from noisy biometric input
 * and a sketch (helper data) needed to reproduce the key.
 */
export interface FuzzyGenResult {
  /** Stable cryptographic key derived from the biometric input */
  key: Uint8Array;
  /** Helper data (sketch) needed to reproduce the key from a similar biometric input */
  sketch: Uint8Array;
}

/**
 * Result of enrollment containing the verification key (public key)
 * and the sketch needed for future signing operations.
 */
export interface EnrollmentResult {
  /** ECDSA public key (verification key) in compressed format */
  vk: Uint8Array;
  /** Fuzzy extractor sketch for reproducing the private key */
  sketch: Uint8Array;
}

/**
 * Configuration options for the fuzzy extractor.
 */
export interface FuzzyConfig {
  /**
   * Size of each block in bytes for the block-wise fuzzy extraction.
   * Larger blocks provide more error tolerance but require more similar inputs.
   * @default 4
   */
  blockSize?: number;

  /**
   * Maximum Hamming distance (in bits) tolerated per block.
   * If the distance exceeds this threshold, reproduction fails.
   * @default 8
   */
  errorThreshold?: number;
}

/**
 * Configuration options for the biometric signer.
 */
export interface SignerConfig {
  /**
   * Fuzzy extractor configuration
   */
  fuzzy?: FuzzyConfig;
}

/**
 * Error thrown when the fuzzy extractor fails to reproduce the key.
 * This typically occurs when the biometric input differs too much from enrollment.
 */
export class FuzzyExtractionError extends Error {
  constructor(
    message: string = "Failed to reproduce key from biometric input"
  ) {
    super(message);
    this.name = "FuzzyExtractionError";
  }
}

/**
 * Error thrown when signature verification fails.
 */
export class SignatureVerificationError extends Error {
  constructor(message: string = "Signature verification failed") {
    super(message);
    this.name = "SignatureVerificationError";
  }
}

/**
 * Expected length of biometric input in bytes.
 * The library expects biometric data to be preprocessed into this fixed length.
 */
export const BIOMETRIC_LENGTH = 32;

/**
 * Length of the derived cryptographic key in bytes.
 */
export const KEY_LENGTH = 32;
