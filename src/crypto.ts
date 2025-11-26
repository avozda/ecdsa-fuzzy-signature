/**
 * Cryptographic utilities for ECDSA operations and key derivation.
 *
 * This module provides wrappers around the @noble/curves library for
 * ECDSA signing and verification on the secp256k1 curve, as well as
 * key derivation functions to convert raw entropy into valid ECDSA keys.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { KEY_LENGTH } from "./types.js";

/** Application-specific info string for ECDSA key derivation */
const ECDSA_KEY_INFO = "ecdsa-secp256k1-key";

/** Application-specific info string for signing nonce derivation */
const SIGNING_NONCE_INFO = "ecdsa-signing-nonce";

/**
 * Derives an ECDSA private key from raw entropy using HKDF.
 *
 * The derived key is reduced modulo the curve order to ensure it's
 * a valid secp256k1 private key (1 <= key < n).
 *
 * @param entropy - Raw entropy bytes (typically 32 bytes from fuzzy extractor)
 * @param salt - Optional salt for domain separation
 * @returns Valid ECDSA private key as Uint8Array
 */
export function derivePrivateKey(
  entropy: Uint8Array,
  salt: Uint8Array = new Uint8Array(0)
): Uint8Array {
  // Use HKDF to derive key material
  // We derive extra bytes to reduce bias when reducing modulo curve order
  const keyMaterial = hkdf(sha256, entropy, salt, ECDSA_KEY_INFO, 64);

  // Convert to bigint and reduce modulo curve order
  const n = secp256k1.CURVE.n;
  let keyNum = bytesToBigInt(keyMaterial);

  // Reduce modulo (n - 1) and add 1 to ensure key is in range [1, n-1]
  keyNum = (keyNum % (n - 1n)) + 1n;

  return bigIntToBytes(keyNum, KEY_LENGTH);
}

/**
 * Computes the ECDSA public key from a private key.
 *
 * @param privateKey - ECDSA private key as Uint8Array
 * @param compressed - Whether to return compressed format (default: true)
 * @returns Public key as Uint8Array (33 bytes compressed, 65 bytes uncompressed)
 */
export function getPublicKey(
  privateKey: Uint8Array,
  compressed: boolean = true
): Uint8Array {
  return secp256k1.getPublicKey(privateKey, compressed);
}

/**
 * Signs a message using ECDSA with the secp256k1 curve.
 *
 * The signature follows RFC 6979 for deterministic nonce generation,
 * ensuring the same message and key always produce the same signature.
 *
 * @param message - Message to sign (will be hashed with SHA-256)
 * @param privateKey - ECDSA private key
 * @returns DER-encoded signature as Uint8Array
 */
export function signMessage(
  message: Uint8Array,
  privateKey: Uint8Array
): Uint8Array {
  // Hash the message first
  const messageHash = sha256(message);

  // Sign the hash using secp256k1 with lowS for malleability protection
  const signature = secp256k1.sign(messageHash, privateKey, { lowS: true });

  // Return compact signature format (r || s, 64 bytes)
  return signature.toCompactRawBytes();
}

/**
 * Verifies an ECDSA signature against a message and public key.
 *
 * @param message - Original message that was signed
 * @param signature - Signature to verify (compact format)
 * @param publicKey - ECDSA public key
 * @returns true if signature is valid, false otherwise
 */
export function verifySignature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  try {
    // Hash the message
    const messageHash = sha256(message);

    // Verify the signature
    return secp256k1.verify(signature, messageHash, publicKey, { lowS: true });
  } catch {
    // Any error during verification means invalid signature
    return false;
  }
}

/**
 * Converts a byte array to a bigint (big-endian).
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Converts a bigint to a byte array of specified length (big-endian).
 */
function bigIntToBytes(num: bigint, length: number): Uint8Array {
  const result = new Uint8Array(length);
  let temp = num;
  for (let i = length - 1; i >= 0; i--) {
    result[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return result;
}

/**
 * Validates that a byte array represents a valid secp256k1 private key.
 *
 * @param key - Byte array to validate
 * @returns true if key is valid, false otherwise
 */
export function isValidPrivateKey(key: Uint8Array): boolean {
  if (key.length !== KEY_LENGTH) {
    return false;
  }

  try {
    const keyNum = bytesToBigInt(key);
    const n = secp256k1.CURVE.n;
    return keyNum > 0n && keyNum < n;
  } catch {
    return false;
  }
}

/**
 * Validates that a byte array represents a valid secp256k1 public key.
 *
 * @param key - Byte array to validate (33 or 65 bytes)
 * @returns true if key is valid, false otherwise
 */
export function isValidPublicKey(key: Uint8Array): boolean {
  try {
    // This will throw if the key is invalid
    secp256k1.ProjectivePoint.fromHex(key);
    return true;
  } catch {
    return false;
  }
}
