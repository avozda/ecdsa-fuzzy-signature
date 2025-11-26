/**
 * Fuzzy Extractor implementation based on the code-and-hash construction.
 *
 * This implements a secure sketch that tolerates small differences in the input
 * biometric data while producing consistent cryptographic keys. The construction
 * is based on the work by Dodis et al., "Fuzzy Extractors: How to Generate Strong
 * Keys from Biometrics and Other Noisy Data".
 *
 * Security note: The security of this scheme depends on the min-entropy of the
 * biometric input and the error tolerance parameters. The caller must ensure
 * that the biometric data has sufficient entropy after accounting for the
 * information leaked through the sketch.
 */

import { sha256 } from "@noble/hashes/sha256.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import {
  FuzzyGenResult,
  FuzzyConfig,
  FuzzyExtractionError,
  KEY_LENGTH,
} from "./types.js";

/** Default block size for the fuzzy extractor */
const DEFAULT_BLOCK_SIZE = 4;

/** Default error threshold (bits per block) */
const DEFAULT_ERROR_THRESHOLD = 8;

/** Magic bytes to identify sketch format version */
const SKETCH_VERSION = new Uint8Array([0x01, 0x00]);

/**
 * Counts the number of differing bits (Hamming distance) between two byte arrays.
 */
function hammingDistance(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) {
    throw new Error("Arrays must have equal length for Hamming distance");
  }
  let distance = 0;
  for (let i = 0; i < a.length; i++) {
    let xor = a[i] ^ b[i];
    while (xor) {
      distance += xor & 1;
      xor >>>= 1;
    }
  }
  return distance;
}

/**
 * Computes the Hamming distance for a single block.
 */
function blockHammingDistance(
  a: Uint8Array,
  b: Uint8Array,
  start: number,
  blockSize: number
): number {
  let distance = 0;
  const end = Math.min(start + blockSize, a.length);
  for (let i = start; i < end; i++) {
    let xor = a[i] ^ b[i];
    while (xor) {
      distance += xor & 1;
      xor >>>= 1;
    }
  }
  return distance;
}

/**
 * XORs two byte arrays of equal length.
 */
function xorArrays(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) {
    throw new Error("Arrays must have equal length for XOR");
  }
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

/**
 * Encodes a locker value using a simple repetition code.
 * Each bit of the locker is repeated multiple times to allow error correction.
 *
 * @param locker - The random locker value to encode
 * @param repetitions - Number of times each bit is repeated
 * @returns Encoded codeword
 */
function encodeLocker(locker: Uint8Array, repetitions: number): Uint8Array {
  const encoded = new Uint8Array(locker.length * repetitions);
  for (let i = 0; i < locker.length; i++) {
    for (let r = 0; r < repetitions; r++) {
      encoded[i * repetitions + r] = locker[i];
    }
  }
  return encoded;
}

/**
 * Decodes a noisy codeword using majority voting on each byte group.
 *
 * @param noisy - The noisy codeword to decode
 * @param repetitions - Number of repetitions used in encoding
 * @returns Decoded locker value
 */
function decodeWithMajority(
  noisy: Uint8Array,
  repetitions: number
): Uint8Array {
  const lockerLength = Math.floor(noisy.length / repetitions);
  const decoded = new Uint8Array(lockerLength);

  for (let i = 0; i < lockerLength; i++) {
    // For each bit position, count votes across repetitions
    const bitCounts = new Array(8).fill(0);

    for (let r = 0; r < repetitions; r++) {
      const byte = noisy[i * repetitions + r];
      for (let bit = 0; bit < 8; bit++) {
        if (byte & (1 << bit)) {
          bitCounts[bit]++;
        }
      }
    }

    // Majority vote for each bit
    let result = 0;
    for (let bit = 0; bit < 8; bit++) {
      if (bitCounts[bit] > repetitions / 2) {
        result |= 1 << bit;
      }
    }
    decoded[i] = result;
  }

  return decoded;
}

/**
 * Serializes the sketch data including version and parameters.
 */
function serializeSketch(
  lockDiff: Uint8Array,
  lockerHash: Uint8Array,
  blockSize: number,
  errorThreshold: number,
  repetitions: number
): Uint8Array {
  const params = new Uint8Array(4);
  params[0] = blockSize;
  params[1] = errorThreshold;
  params[2] = repetitions;
  params[3] = 0; // Reserved

  const result = new Uint8Array(
    SKETCH_VERSION.length + params.length + lockerHash.length + lockDiff.length
  );

  let offset = 0;
  result.set(SKETCH_VERSION, offset);
  offset += SKETCH_VERSION.length;
  result.set(params, offset);
  offset += params.length;
  result.set(lockerHash, offset);
  offset += lockerHash.length;
  result.set(lockDiff, offset);

  return result;
}

/**
 * Deserializes a sketch to extract parameters and data.
 */
function deserializeSketch(sketch: Uint8Array): {
  lockDiff: Uint8Array;
  lockerHash: Uint8Array;
  blockSize: number;
  errorThreshold: number;
  repetitions: number;
} {
  // Check version
  if (sketch[0] !== SKETCH_VERSION[0] || sketch[1] !== SKETCH_VERSION[1]) {
    throw new FuzzyExtractionError("Invalid sketch version");
  }

  const blockSize = sketch[2];
  const errorThreshold = sketch[3];
  const repetitions = sketch[4];

  const paramsEnd = SKETCH_VERSION.length + 4;
  const hashEnd = paramsEnd + 32; // SHA-256 hash length

  const lockerHash = sketch.slice(paramsEnd, hashEnd);
  const lockDiff = sketch.slice(hashEnd);

  return { lockDiff, lockerHash, blockSize, errorThreshold, repetitions };
}

/**
 * Generates a stable key and sketch from a biometric input.
 *
 * This is the "Gen" operation of the fuzzy extractor. It produces a
 * cryptographic key and a sketch (helper data). The sketch can later be
 * used with a similar biometric input to reproduce the same key.
 *
 * @param b - Biometric input as a fixed-length Uint8Array
 * @param config - Optional configuration parameters
 * @returns Object containing the derived key and sketch
 *
 * @example
 * ```typescript
 * const biometric = new Uint8Array(32); // Your preprocessed biometric data
 * const { key, sketch } = fuzzyGen(biometric);
 * // Store sketch for later use; key is used for cryptographic operations
 * ```
 */
export function fuzzyGen(
  b: Uint8Array,
  config: FuzzyConfig = {}
): FuzzyGenResult {
  const blockSize = config.blockSize ?? DEFAULT_BLOCK_SIZE;
  const errorThreshold = config.errorThreshold ?? DEFAULT_ERROR_THRESHOLD;

  // Number of repetitions for error correction (higher = more tolerance, less security)
  // We use 3 repetitions which allows correcting up to ~33% bit errors per block
  const repetitions = 3;

  // Generate random locker value (this is what we'll recover)
  const locker = randomBytes(KEY_LENGTH);

  // Encode the locker with repetition for error correction
  const encodedLocker = encodeLocker(locker, repetitions);

  // Expand biometric to match encoded locker size
  // We use HKDF to expand the biometric hash to the needed size
  const expandedB = hkdf(
    sha256,
    b,
    new Uint8Array(0),
    "fuzzy-expand",
    encodedLocker.length
  );

  // Compute the difference (secure sketch)
  const lockDiff = xorArrays(expandedB, encodedLocker);

  // Compute hash of locker for verification during reproduction
  const lockerHash = sha256(locker);

  // Serialize the sketch with parameters
  const sketch = serializeSketch(
    lockDiff,
    lockerHash,
    blockSize,
    errorThreshold,
    repetitions
  );

  // Derive the final key from the locker using HKDF
  const key = hkdf(sha256, locker, new Uint8Array(0), "fuzzy-key", KEY_LENGTH);

  return { key, sketch };
}

/**
 * Reproduces the key from a biometric input and sketch.
 *
 * This is the "Rep" operation of the fuzzy extractor. Given a biometric
 * input that is "close enough" to the original enrollment biometric and
 * the sketch produced during enrollment, it reproduces the same key.
 *
 * @param b - Biometric input as a fixed-length Uint8Array
 * @param sketch - Sketch produced during enrollment (from fuzzyGen)
 * @returns The reproduced key, or null if reproduction fails
 * @throws FuzzyExtractionError if the biometric differs too much or sketch is invalid
 *
 * @example
 * ```typescript
 * const biometric = new Uint8Array(32); // Similar to enrollment biometric
 * const key = fuzzyRep(biometric, storedSketch);
 * if (key === null) {
 *   console.error('Biometric mismatch');
 * }
 * ```
 */
export function fuzzyRep(b: Uint8Array, sketch: Uint8Array): Uint8Array | null {
  try {
    const { lockDiff, lockerHash, repetitions } = deserializeSketch(sketch);

    // Expand biometric to match lock diff size
    const expandedB = hkdf(
      sha256,
      b,
      new Uint8Array(0),
      "fuzzy-expand",
      lockDiff.length
    );

    // Compute noisy codeword: expandedB ⊕ lockDiff = expandedB ⊕ (origExpandedB ⊕ encodedLocker)
    // If expandedB ≈ origExpandedB, this gives us a noisy version of encodedLocker
    const noisyCodeword = xorArrays(expandedB, lockDiff);

    // Decode using majority voting to recover the locker
    const recoveredLocker = decodeWithMajority(noisyCodeword, repetitions);

    // Verify the recovered locker by checking its hash
    const recoveredHash = sha256(recoveredLocker);

    // Compare hashes
    let hashMatch = true;
    for (let i = 0; i < lockerHash.length; i++) {
      if (lockerHash[i] !== recoveredHash[i]) {
        hashMatch = false;
        break;
      }
    }

    if (!hashMatch) {
      return null;
    }

    // Derive the final key from the recovered locker
    const key = hkdf(
      sha256,
      recoveredLocker,
      new Uint8Array(0),
      "fuzzy-key",
      KEY_LENGTH
    );

    return key;
  } catch (error) {
    if (error instanceof FuzzyExtractionError) {
      throw error;
    }
    return null;
  }
}

/**
 * Utility function to compute the bit-level similarity between two biometric inputs.
 * Useful for testing and calibrating error thresholds.
 *
 * @param a - First biometric input
 * @param b - Second biometric input
 * @returns Object with total bits, differing bits, and similarity percentage
 */
export function computeSimilarity(
  a: Uint8Array,
  b: Uint8Array
): {
  totalBits: number;
  differingBits: number;
  similarity: number;
} {
  const minLen = Math.min(a.length, b.length);
  const aSlice = a.slice(0, minLen);
  const bSlice = b.slice(0, minLen);

  const differingBits = hammingDistance(aSlice, bSlice);
  const totalBits = minLen * 8;
  const similarity = 1 - differingBits / totalBits;

  return { totalBits, differingBits, similarity };
}
