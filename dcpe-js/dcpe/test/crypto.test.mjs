import {
    computeAuthHash,
    encryptVector,
    decryptVector,
    shuffle,
    unshuffle,
    generateNoiseVector
} from "../crypto/index.js";
import { VectorEncryptionKey, ScalingFactor, EncryptionKey } from "../keys/index.js";
import { InvalidKeyError, DecryptError } from "../exceptions/index.js";

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

            expect(authHash).toBeDefined();
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
            expect(decryptedVector.length).toBe(plaintextVector.length);
            for (let i = 0; i < plaintextVector.length; i++) {
                expect(decryptedVector[i]).toBeCloseTo(plaintextVector[i], 1); // 1 decimal place precision
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
});