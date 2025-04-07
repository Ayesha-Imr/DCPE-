import crypto from 'crypto';
import { create, all } from 'mathjs';
import { InvalidKeyError, DecryptError } from '../exceptions/index.js';
import { VectorEncryptionKey, ScalingFactor, EncryptionKey } from '../keys/index.js';


const math = create(all);

// Constants
const SHUFFLE_KEY = "One Ring to rule them all, One Ring to find them, One Ring to bring them all, and in the darkness bind them";

/**
 * Represents an authentication hash.
 */
class AuthHash {
    constructor(hashBytes) {
        if (!Buffer.isBuffer(hashBytes)) {
            throw new TypeError("AuthHash must be initialized with a Buffer");
        }
        if (hashBytes.length !== 32) {
            throw new Error("AuthHash must be 32 bytes long");
        }
        this.hashBytes = hashBytes;
    }

    getBytes() {
        return this.hashBytes;
    }

    equals(other) {
        return other instanceof AuthHash && this.hashBytes.equals(other.hashBytes);
    }

    toString() {
        return `AuthHash(${this.hashBytes.toString('hex')})`;
    }
}

/**
 * Generates a random vector sampled from a multivariate normal distribution.
 * @param {number} dimensionality - The dimensionality of the vector.
 * @returns {Array<number>} - The sampled vector.
 */
function sampleNormalVector(dimensionality) {
    return Array.from({ length: dimensionality }, () => {
      // Use crypto instead of Math.random()
      const u1Bytes = crypto.randomBytes(4);
      const u2Bytes = crypto.randomBytes(4);
      const u1 = u1Bytes.readUInt32LE(0) / 0x100000000;
      const u2 = u2Bytes.readUInt32LE(0) / 0x100000000;
      const z0 = Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2);
      return z0;
    });
  }


/**
 * Generates a random uniform point in the range [0, 1).
 * 
 * This function uses cryptographic randomness to ensure high-quality random values.
 * It generates 4 random bytes, interprets them as a 32-bit unsigned integer, 
 * and then normalizes the value to a floating-point number in the range [0, 1).
 * 
 * @returns {number} A random floating-point number in the range [0, 1).
 */
function sampleUniformPoint() {
    const bytes = crypto.randomBytes(4);
    return bytes.readUInt32LE(0) / 0x100000000;
  }

/**
 * Calculates a uniform point within an n-dimensional ball.
 * @param {ScalingFactor} scalingFactor - The scaling factor.
 * @param {number} approximationFactor - The approximation factor.
 * @param {number} uniformPoint - The sampled uniform point.
 * @param {number} dimensionality - The dimensionality of the vector.
 * @returns {number} - The calculated point.
 */
function calculateUniformPointInBall(scalingFactor, approximationFactor, uniformPoint, dimensionality) {
    const radius = (scalingFactor.getFactor() / 4) * approximationFactor;
    return radius * Math.pow(uniformPoint, 1 / dimensionality);
}

/**
 * Normalizes a sampled vector.
 * @param {Array<number>} vector - The sampled vector.
 * @param {number} scale - The scaling factor.
 * @returns {Array<number>} - The normalized vector.
 */
function normalizeVector(vector, scale) {
    const norm = math.norm(vector);
    return vector.map((val) => (val * scale) / norm);
}

/**
 * Generates a normalized noise vector for encryption.
 * @param {VectorEncryptionKey} key - The encryption key.
 * @param {Buffer} iv - The initialization vector.
 * @param {number} approximationFactor - The approximation factor.
 * @param {number} dimensionality - The dimensionality of the vector.
 * @returns {Array<number>} - The noise vector.
 */
function generateNoiseVector(key, iv, approximationFactor, dimensionality) {
    if (!key) {
        throw new Error("Key is required for noise vector generation");
    }
    if (!iv || !Buffer.isBuffer(iv)) {
        throw new Error("IV must be a valid Buffer for noise vector generation");
    }
    if (!Number.isFinite(approximationFactor) || approximationFactor <= 0) {
        throw new Error("Approximation factor must be a positive number");
    }
    if (!Number.isInteger(dimensionality) || dimensionality <= 0) {
        throw new Error("Dimensionality must be a positive integer");
    }
    
    const normalVector = sampleNormalVector(dimensionality);
    const uniformPoint = sampleUniformPoint();
    const scaledPoint = calculateUniformPointInBall(key.scalingFactor, approximationFactor, uniformPoint, dimensionality);
    return normalizeVector(normalVector, scaledPoint);
}


/**
 * Creates a random number generator (RNG) function based on a given cryptographic key.
 * The RNG function generates pseudo-random numbers in the range [0, 1) using HMAC with SHA-256.
 *
 * @param {Object} key - The cryptographic key used to seed the RNG. It must have a `getBytes` method
 *                       that returns the key as a byte array.
 * @returns {Function} A function that generates a pseudo-random number between 0 (inclusive) and 1 (exclusive)
 *                     each time it is called.
 */
function createRngFromKey(key) {
    return function() {
      const hmac = crypto.createHmac('sha256', key.getBytes());
      hmac.update(Buffer.from([this.counter++ & 0xFF]));
      const bytes = hmac.digest();
      return bytes.readUInt32LE(0) / 0x100000000;
    }.bind({ counter: 0 });
  }

/**
 * Shuffles an array deterministically based on a key.
 * @param {EncryptionKey} key - The encryption key used for deterministic shuffling.
 * @param {Array} inputArray - The array to shuffle.
 * @returns {Array} - The shuffled array.
 */
function shuffle(key, inputArray) {
    if (!key || !Array.isArray(inputArray)) {
        throw new Error("Invalid input to shuffle function");
    }

    // Create a deterministic random number generator based on the key
    const rng = createRngFromKey(key);

    // Create an array of indices and shuffle them
    const indices = inputArray.map((_, index) => index);
    for (let i = indices.length - 1; i > 0; i--) {
        const j = Math.floor(rng() * (i + 1));
        [indices[i], indices[j]] = [indices[j], indices[i]];
    }

    // Use the shuffled indices to reorder the input array
    return indices.map((index) => inputArray[index]);
}

/**
 * Unshuffles an array that was shuffled deterministically based on a key.
 * @param {EncryptionKey} key - The encryption key used for deterministic shuffling.
 * @param {Array} shuffledArray - The array to unshuffle.
 * @returns {Array} - The unshuffled array.
 */
/**
 * Reverses the shuffling of an array based on a given key.
 *
 * @param {string} key - A string used to seed the deterministic random number generator.
 * @param {Array} shuffledArray - The array that was previously shuffled and needs to be restored to its original order.
 * @returns {Array} - The original array restored to its unshuffled order.
 * @throws {Error} - Throws an error if the key is not provided or if the shuffledArray is not an array.
 *
 * @description
 * This function assumes that the array was shuffled using a deterministic algorithm
 * based on the same key. It recreates the shuffle permutation using a seeded random
 * number generator and then reverses the shuffle to restore the original order.
 *
 * Note: The function relies on the existence of `createRngFromKey`, which must generate
 * a deterministic random number generator seeded by the provided key.
 */
function unshuffle(key, shuffledArray) {
    if (!key || !Array.isArray(shuffledArray)) {
        throw new Error("Invalid input to unshuffle function");
    }

    // Create a deterministic random number generator based on the key
    const rng = createRngFromKey(key);

    // First recreate the exact same permutation that was used in the shuffle function
    const indices = Array.from({ length: shuffledArray.length }, (_, i) => i);
    for (let i = indices.length - 1; i > 0; i--) {
        const j = Math.floor(rng() * (i + 1));
        [indices[i], indices[j]] = [indices[j], indices[i]];
    }

    // Create a mapping from shuffled position to original position
    const reverseMap = new Array(indices.length);
    for (let i = 0; i < indices.length; i++) {
        reverseMap[indices[i]] = i;
    }

    // Use the mapping to restore the original order
    return shuffledArray.map((_, i) => shuffledArray[reverseMap[i]]);
}

/**
 * Computes an authentication hash for a vector embedding.
 * @param {VectorEncryptionKey} key - The encryption key.
 * @param {number} approximationFactor - The approximation factor.
 * @param {Buffer} iv - The initialization vector.
 * @param {Array<number>} encryptedVector - The encrypted vector.
 * @returns {AuthHash} - The computed authentication hash.
 */
function computeAuthHash(key, approximationFactor, iv, encryptedVector) {
    const hmac = crypto.createHmac('sha256', key.key.getBytes());
    hmac.update(Buffer.from(Float32Array.of(key.scalingFactor.getFactor()).buffer));
    hmac.update(Buffer.from(Float32Array.of(approximationFactor).buffer));
    hmac.update(iv);
    encryptedVector.forEach((val) => {
        hmac.update(Buffer.from(Float32Array.of(val).buffer));
    });
    return new AuthHash(hmac.digest());
}

/**
 * Encrypts a vector embedding.
 * @param {VectorEncryptionKey} key - The encryption key.
 * @param {number} approximationFactor - The approximation factor.
 * @param {Array<number>} vector - The plaintext vector.
 * @returns {Object} - The encryption result containing ciphertext, IV, and auth hash.
 */
function encryptVector(key, approximationFactor, vector) {
    if (key.scalingFactor.getFactor() === 0) {
        throw new InvalidKeyError("Scaling factor cannot be zero");
    }

    const iv = crypto.randomBytes(12);
    const noiseVector = generateNoiseVector(key, iv, approximationFactor, vector.length);
    const ciphertext = vector.map((val, i) => key.scalingFactor.getFactor() * val + noiseVector[i]);

    if (!ciphertext.every((val) => Number.isFinite(val))) {
        throw new Error("Overflow error: Embedding or approximation factor too large.");
    }

    const authHash = computeAuthHash(key, approximationFactor, iv, ciphertext);

    return { ciphertext, iv, authHash };
}

/**
 * Decrypts an encrypted vector embedding.
 * @param {VectorEncryptionKey} key - The encryption key.
 * @param {number} approximationFactor - The approximation factor.
 * @param {Object} encryptedResult - The encryption result containing ciphertext, IV, and auth hash.
 * @returns {Array<number>} - The decrypted vector.
 */
function decryptVector(key, approximationFactor, encryptedResult) {
    if (key.scalingFactor.getFactor() === 0) {
        throw new InvalidKeyError("Scaling factor cannot be zero");
    }

    const { ciphertext, iv, authHash } = encryptedResult;

    if (!computeAuthHash(key, approximationFactor, iv, ciphertext).equals(authHash)) {
        throw new DecryptError("Authentication hash mismatch");
    }

    const noiseVector = generateNoiseVector(key, iv, approximationFactor, ciphertext.length);
    return ciphertext.map((val, i) => (val - noiseVector[i]) / key.scalingFactor.getFactor());
}

export {
    AuthHash,
    encryptVector,
    decryptVector,
    computeAuthHash,
    generateNoiseVector,
    shuffle,
    unshuffle,
    sampleNormalVector,
    sampleUniformPoint
};