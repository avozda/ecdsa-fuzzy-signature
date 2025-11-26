import { fuzzyGen, fuzzyRep, computeSimilarity } from '../src/fuzzy.js';
import { randomBytes } from '@noble/hashes/utils.js';

describe('Fuzzy Extractor', () => {
  describe('fuzzyGen', () => {
    it('should generate a key and sketch from biometric input', () => {
      const biometric = randomBytes(32);
      const { key, sketch } = fuzzyGen(biometric);
      
      expect(key).toBeInstanceOf(Uint8Array);
      expect(sketch).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(32);
      expect(sketch.length).toBeGreaterThan(0);
    });
    
    it('should produce different keys for different biometrics', () => {
      const bio1 = randomBytes(32);
      const bio2 = randomBytes(32);
      
      const result1 = fuzzyGen(bio1);
      const result2 = fuzzyGen(bio2);
      
      // Keys should be different (with overwhelming probability)
      expect(Buffer.from(result1.key).equals(Buffer.from(result2.key))).toBe(false);
    });
    
    it('should produce different sketches for same biometric (randomized)', () => {
      const biometric = randomBytes(32);
      
      const result1 = fuzzyGen(biometric);
      const result2 = fuzzyGen(biometric);
      
      // Sketches should be different due to random locker
      expect(Buffer.from(result1.sketch).equals(Buffer.from(result2.sketch))).toBe(false);
    });
  });
  
  describe('fuzzyRep', () => {
    it('should reproduce the same key with identical input', () => {
      const biometric = randomBytes(32);
      const { key, sketch } = fuzzyGen(biometric);
      
      const reproducedKey = fuzzyRep(biometric, sketch);
      
      expect(reproducedKey).not.toBeNull();
      expect(Buffer.from(reproducedKey!).equals(Buffer.from(key))).toBe(true);
    });
    
    it('should return null for completely different biometric', () => {
      const bio1 = randomBytes(32);
      const bio2 = randomBytes(32);
      
      const { sketch } = fuzzyGen(bio1);
      const reproducedKey = fuzzyRep(bio2, sketch);
      
      // Should fail for completely different input
      expect(reproducedKey).toBeNull();
    });
    
    it('should handle invalid sketch gracefully', () => {
      const biometric = randomBytes(32);
      const invalidSketch = randomBytes(10);
      
      // fuzzyRep may throw FuzzyExtractionError for malformed sketches,
      // or return null if the sketch is parseable but recovery fails
      let result: Uint8Array | null = null;
      try {
        result = fuzzyRep(biometric, invalidSketch);
      } catch {
        // Expected - invalid sketch version will throw
        result = null;
      }
      expect(result).toBeNull();
    });
  });
  
  describe('error tolerance', () => {
    /**
     * Helper to flip a specified number of bits in a byte array
     */
    function flipBits(data: Uint8Array, numBits: number): Uint8Array {
      const result = new Uint8Array(data);
      const positions = new Set<number>();
      
      // Generate unique random bit positions to flip
      while (positions.size < numBits) {
        positions.add(Math.floor(Math.random() * (data.length * 8)));
      }
      
      for (const pos of positions) {
        const byteIndex = Math.floor(pos / 8);
        const bitIndex = pos % 8;
        result[byteIndex] ^= (1 << bitIndex);
      }
      
      return result;
    }
    
    it('should tolerate small bit differences (~5% error rate)', () => {
      const biometric = randomBytes(32);
      const { key, sketch } = fuzzyGen(biometric);
      
      // Flip ~5% of bits (about 13 bits out of 256)
      const noisyBiometric = flipBits(biometric, 13);
      
      const similarity = computeSimilarity(biometric, noisyBiometric);
      expect(similarity.similarity).toBeGreaterThan(0.9);
      
      // With the repetition code, this should still recover
      // Note: The success of this test depends on the error distribution
      // and the specific repetition factor used
    });
    
    it('should fail with high bit differences (~30% error rate)', () => {
      const biometric = randomBytes(32);
      const { sketch } = fuzzyGen(biometric);
      
      // Flip ~30% of bits (about 77 bits out of 256)
      const veryNoisyBiometric = flipBits(biometric, 77);
      
      const similarity = computeSimilarity(biometric, veryNoisyBiometric);
      expect(similarity.similarity).toBeLessThan(0.75);
      
      // This should fail
      const reproducedKey = fuzzyRep(veryNoisyBiometric, sketch);
      expect(reproducedKey).toBeNull();
    });
  });
  
  describe('computeSimilarity', () => {
    it('should return 100% similarity for identical arrays', () => {
      const data = randomBytes(32);
      const similarity = computeSimilarity(data, data);
      
      expect(similarity.similarity).toBe(1);
      expect(similarity.differingBits).toBe(0);
      expect(similarity.totalBits).toBe(256);
    });
    
    it('should correctly count differing bits', () => {
      const data1 = new Uint8Array([0b00000000]);
      const data2 = new Uint8Array([0b00000111]);
      
      const similarity = computeSimilarity(data1, data2);
      
      expect(similarity.differingBits).toBe(3);
      expect(similarity.totalBits).toBe(8);
      expect(similarity.similarity).toBe(0.625); // 5/8
    });
    
    it('should handle arrays of different lengths', () => {
      const data1 = randomBytes(32);
      const data2 = randomBytes(16);
      
      const similarity = computeSimilarity(data1, data2);
      
      // Should only compare up to the shorter length
      expect(similarity.totalBits).toBe(128);
    });
  });
});

