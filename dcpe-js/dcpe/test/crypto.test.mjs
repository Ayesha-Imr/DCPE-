import {
    computeAuthHash,
    encryptVector,
    decryptVector,
    shuffle,
    unshuffle,
    generateNoiseVector,
    sampleNormalVector,
    sampleUniformPoint,
} from "../crypto/index.js";
import { VectorEncryptionKey, ScalingFactor, EncryptionKey, generateRandomKey } from "../keys/index.js";
import { DecryptError, InvalidKeyError } from "../exceptions/index.js";
import { hkdf } from '../crypto/hkdf.js';

describe("Crypto Module", () => {
    const keyBytes = Buffer.from("testkey12345678901234567890123456");
    const scalingFactor = new ScalingFactor(1.5);
    const encryptionKey = new EncryptionKey(keyBytes);
    const vectorKey = new VectorEncryptionKey(scalingFactor, encryptionKey);

    describe("computeAuthHash", () => {
        test("should return a valid AuthHash", () => {
            const iv = Buffer.from("123456789012");
            const encryptedVector = [1.0, 2.0, 3.0];
            const authHash = computeAuthHash(vectorKey, 1.0, iv, encryptedVector);

            expect(authHash.getBytes()).toBeDefined();
            expect(authHash.getBytes().length).toBe(32);
        });

        test("should produce different hashes for different vectors", () => {
            const iv = Buffer.from("123456789012");
            const vector1 = [1.0, 2.0, 3.0];
            const vector2 = [4.0, 5.0, 6.0];
            const hash1 = computeAuthHash(vectorKey, 1.0, iv, vector1);
            const hash2 = computeAuthHash(vectorKey, 1.0, iv, vector2);

            expect(hash1.equals(hash2)).toBe(false);
        });

        test("should throw an error for invalid inputs", () => {
            const iv = Buffer.from("123456789012");
            expect(() => computeAuthHash(vectorKey, 1.0, iv, null)).toThrow();
        });
    });

    describe("shuffle and unshuffle", () => {
        test("shuffle should reorder the array deterministically", () => {
            const inputArray = [1, 2, 3, 4, 5];
            const shuffledArray = shuffle(encryptionKey, inputArray);

            expect(shuffledArray).not.toEqual(inputArray);
            expect(shuffledArray.length).toBe(inputArray.length);
        });

        test("unshuffle should reverse the shuffle operation", () => {
            const inputArray = [1, 2, 3, 4, 5];
            const shuffledArray = shuffle(encryptionKey, inputArray);
            const unshuffledArray = unshuffle(encryptionKey, shuffledArray);

            expect(unshuffledArray).toEqual(inputArray);
        });

        test("shuffle should throw an error for invalid inputs", () => {
            expect(() => shuffle(null, [1, 2, 3])).toThrow();
            expect(() => shuffle(encryptionKey, null)).toThrow();
        });

        test("unshuffle should throw an error for invalid inputs", () => {
            expect(() => unshuffle(null, [1, 2, 3])).toThrow();
            expect(() => unshuffle(encryptionKey, null)).toThrow();
        });
    });

    describe("encryptVector and decryptVector", () => {
        test("should encrypt and decrypt a vector correctly", () => {
            const plaintextVector = [1.0, 2.0, 3.0];
            const approximationFactor = 1.0;

            const encryptedResult = encryptVector(vectorKey, approximationFactor, plaintextVector);
            const decryptedVector = decryptVector(vectorKey, approximationFactor, encryptedResult);

            // Check that each element is "close enough" instead of exactly equal
            for (let i = 0; i < plaintextVector.length; i++) {
                expect(decryptedVector[i]).toBeCloseTo(plaintextVector[i], 1); 
            }
        });

        test("should throw an error if scaling factor is zero", () => {
            const zeroScalingFactor = new ScalingFactor(0);
            const zeroVectorKey = new VectorEncryptionKey(zeroScalingFactor, encryptionKey);
            const plaintextVector = [1.0, 2.0, 3.0];

            expect(() => encryptVector(zeroVectorKey, 1.0, plaintextVector)).toThrow(InvalidKeyError);
        });

        test("should throw an error if authentication hash does not match", () => {
            const plaintextVector = [1.0, 2.0, 3.0];
            const approximationFactor = 1.0;

            const encryptedResult = encryptVector(vectorKey, approximationFactor, plaintextVector);
            encryptedResult.authHash = Buffer.from("invalidhash12345678901234567890123456");

            expect(() => decryptVector(vectorKey, approximationFactor, encryptedResult)).toThrow(DecryptError);
        });

        test("should throw an error for invalid inputs", () => {
            expect(() => encryptVector(null, 1.0, [1.0, 2.0, 3.0])).toThrow();
            expect(() => decryptVector(vectorKey, 1.0, null)).toThrow();
        });
    });

    describe("generateNoiseVector", () => {
        test("should generate a noise vector of the correct length", () => {
            const iv = Buffer.from("123456789012");
            const dimensionality = 3;
            const noiseVector = generateNoiseVector(vectorKey, iv, 1.0, dimensionality);

            expect(noiseVector.length).toBe(dimensionality);
        });

        test("should throw an error for invalid inputs", () => {
            const iv = Buffer.from("123456789012");
            expect(() => generateNoiseVector(null, iv, 1.0, 3)).toThrow();
            expect(() => generateNoiseVector(vectorKey, null, 1.0, 3)).toThrow();
        });
    });
    describe('Cryptographic Randomness', () => {
        test('sampleNormalVector should generate vector of requested size', () => {
            const size = 10;
            const vector = sampleNormalVector(size);
            expect(vector.length).toBe(size);
        });
        
        test('sampleNormalVector should generate different values on each call', () => {
            const size = 10;
            const vector1 = sampleNormalVector(size);
            const vector2 = sampleNormalVector(size);
            
            // Check that the vectors are not identical
            // (very small probability they would be by chance)
            let allEqual = true;
            for (let i = 0; i < size; i++) {
                if (vector1[i] !== vector2[i]) {
                    allEqual = false;
                    break;
                }
            }
            expect(allEqual).toBe(false);
        });
        
        test('sampleUniformPoint should return value between 0 and 1', () => {
            const point = sampleUniformPoint();
            expect(point).toBeGreaterThanOrEqual(0);
            expect(point).toBeLessThan(1);
        });
        
        test('sampleUniformPoint should generate different values on each call', () => {
            const points = new Set();
            for (let i = 0; i < 10; i++) {
                points.add(sampleUniformPoint());
            }
            // With cryptographic randomness, very high chance all 10 values are unique
            expect(points.size).toBeGreaterThan(5);
        });
    });
});


describe('HKDF Module', () => {
    test('should derive keys of requested length', () => {
        const ikm = Buffer.from('input key material');
        const length = 32;
        const salt = Buffer.from('salt value');
        const info = Buffer.from('context info');
        
        const derivedKey = hkdf(ikm, length, salt, info);
        
        expect(derivedKey.length).toBe(length);
    });
    
    test('should derive consistent keys given the same inputs', () => {
        const ikm = Buffer.from('input key material');
        const length = 32;
        const salt = Buffer.from('salt value');
        const info = Buffer.from('context info');
        
        const key1 = hkdf(ikm, length, salt, info);
        const key2 = hkdf(ikm, length, salt, info);
        
        expect(Buffer.compare(key1, key2)).toBe(0); // 0 means buffers are equal
    });
    
    test('should derive different keys when inputs change', () => {
        const ikm = Buffer.from('input key material');
        const length = 32;
        const salt1 = Buffer.from('salt value 1');
        const salt2 = Buffer.from('salt value 2');
        const info = Buffer.from('context info');
        
        const key1 = hkdf(ikm, length, salt1, info);
        const key2 = hkdf(ikm, length, salt2, info);
        
        expect(Buffer.compare(key1, key2)).not.toBe(0); // Buffers should be different
    });
    
    test('should handle default values for salt and info', () => {
        const ikm = Buffer.from('input key material');
        const length = 32;
        
        expect(() => hkdf(ikm, length)).not.toThrow();
        expect(hkdf(ikm, length).length).toBe(length);
    });
    
    test('should throw for invalid inputs', () => {
        expect(() => hkdf('not a buffer', 32)).toThrow(TypeError);
    });
});