import {
  derivePrivateKey,
  getPublicKey,
  signMessage,
  verifySignature,
  isValidPrivateKey,
  isValidPublicKey,
} from '../src/crypto.js';
import { randomBytes } from '@noble/hashes/utils.js';

describe('Crypto Utilities', () => {
  describe('derivePrivateKey', () => {
    it('should derive a valid private key from entropy', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      
      expect(privateKey).toBeInstanceOf(Uint8Array);
      expect(privateKey.length).toBe(32);
      expect(isValidPrivateKey(privateKey)).toBe(true);
    });
    
    it('should produce deterministic keys from same entropy', () => {
      const entropy = randomBytes(32);
      
      const key1 = derivePrivateKey(entropy);
      const key2 = derivePrivateKey(entropy);
      
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(true);
    });
    
    it('should produce different keys from different entropy', () => {
      const entropy1 = randomBytes(32);
      const entropy2 = randomBytes(32);
      
      const key1 = derivePrivateKey(entropy1);
      const key2 = derivePrivateKey(entropy2);
      
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(false);
    });
    
    it('should produce different keys with different salts', () => {
      const entropy = randomBytes(32);
      const salt1 = new TextEncoder().encode('salt1');
      const salt2 = new TextEncoder().encode('salt2');
      
      const key1 = derivePrivateKey(entropy, salt1);
      const key2 = derivePrivateKey(entropy, salt2);
      
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(false);
    });
  });
  
  describe('getPublicKey', () => {
    it('should compute public key from private key (compressed)', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = getPublicKey(privateKey, true);
      
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(33); // Compressed format
      expect(isValidPublicKey(publicKey)).toBe(true);
    });
    
    it('should compute public key from private key (uncompressed)', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = getPublicKey(privateKey, false);
      
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(65); // Uncompressed format
      expect(isValidPublicKey(publicKey)).toBe(true);
    });
    
    it('should produce deterministic public keys', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      
      const pub1 = getPublicKey(privateKey);
      const pub2 = getPublicKey(privateKey);
      
      expect(Buffer.from(pub1).equals(Buffer.from(pub2))).toBe(true);
    });
  });
  
  describe('signMessage and verifySignature', () => {
    it('should sign and verify a message', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = getPublicKey(privateKey);
      
      const message = new TextEncoder().encode('Hello, World!');
      const signature = signMessage(message, privateKey);
      
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64); // Compact signature format
      
      const isValid = verifySignature(message, signature, publicKey);
      expect(isValid).toBe(true);
    });
    
    it('should fail verification with wrong message', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = getPublicKey(privateKey);
      
      const message = new TextEncoder().encode('Hello, World!');
      const signature = signMessage(message, privateKey);
      
      const wrongMessage = new TextEncoder().encode('Hello, Universe!');
      const isValid = verifySignature(wrongMessage, signature, publicKey);
      
      expect(isValid).toBe(false);
    });
    
    it('should fail verification with wrong public key', () => {
      const entropy1 = randomBytes(32);
      const entropy2 = randomBytes(32);
      
      const privateKey1 = derivePrivateKey(entropy1);
      const privateKey2 = derivePrivateKey(entropy2);
      const publicKey2 = getPublicKey(privateKey2);
      
      const message = new TextEncoder().encode('Hello, World!');
      const signature = signMessage(message, privateKey1);
      
      const isValid = verifySignature(message, signature, publicKey2);
      expect(isValid).toBe(false);
    });
    
    it('should fail verification with corrupted signature', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = getPublicKey(privateKey);
      
      const message = new TextEncoder().encode('Hello, World!');
      const signature = signMessage(message, privateKey);
      
      // Corrupt the signature
      const corruptedSignature = new Uint8Array(signature);
      corruptedSignature[0] ^= 0xff;
      
      const isValid = verifySignature(message, corruptedSignature, publicKey);
      expect(isValid).toBe(false);
    });
    
    it('should produce deterministic signatures (RFC 6979)', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      
      const message = new TextEncoder().encode('Hello, World!');
      
      const sig1 = signMessage(message, privateKey);
      const sig2 = signMessage(message, privateKey);
      
      expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(true);
    });
    
    it('should handle empty message', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = getPublicKey(privateKey);
      
      const message = new Uint8Array(0);
      const signature = signMessage(message, privateKey);
      
      const isValid = verifySignature(message, signature, publicKey);
      expect(isValid).toBe(true);
    });
    
    it('should handle large message', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = getPublicKey(privateKey);
      
      // Create a message larger than typical (50KB)
      const message = new Uint8Array(50000);
      for (let i = 0; i < 50000; i++) {
        message[i] = i % 256;
      }
      const signature = signMessage(message, privateKey);
      
      const isValid = verifySignature(message, signature, publicKey);
      expect(isValid).toBe(true);
    });
  });
  
  describe('isValidPrivateKey', () => {
    it('should return true for valid private key', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      
      expect(isValidPrivateKey(privateKey)).toBe(true);
    });
    
    it('should return false for all-zero key', () => {
      const zeroKey = new Uint8Array(32);
      expect(isValidPrivateKey(zeroKey)).toBe(false);
    });
    
    it('should return false for wrong length', () => {
      const shortKey = randomBytes(16);
      const longKey = randomBytes(64);
      
      expect(isValidPrivateKey(shortKey)).toBe(false);
      expect(isValidPrivateKey(longKey)).toBe(false);
    });
  });
  
  describe('isValidPublicKey', () => {
    it('should return true for valid compressed public key', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = getPublicKey(privateKey, true);
      
      expect(isValidPublicKey(publicKey)).toBe(true);
    });
    
    it('should return true for valid uncompressed public key', () => {
      const entropy = randomBytes(32);
      const privateKey = derivePrivateKey(entropy);
      const publicKey = getPublicKey(privateKey, false);
      
      expect(isValidPublicKey(publicKey)).toBe(true);
    });
    
    it('should return false for invalid public key', () => {
      const invalidKey = randomBytes(33);
      expect(isValidPublicKey(invalidKey)).toBe(false);
    });
    
    it('should return false for wrong length', () => {
      const shortKey = randomBytes(16);
      expect(isValidPublicKey(shortKey)).toBe(false);
    });
  });
});

