import { encryptVector, decryptVector, shuffle, unshuffle, computeAuthHash } from '../crypto/index.js';
import { KeyIdHeader, encodeVectorMetadata, decodeVersionPrefixedValue } from '../headers/index.js';
import { VectorEncryptionKey, EncryptionKey, ScalingFactor } from '../keys/index.js';
import { InvalidInputError, DecryptError } from '../exceptions/index.js';
import crypto from 'crypto';

/**
 * RagEncryptionClient: High-level interface for encryption and decryption.
 */
class RagEncryptionClient {
    /**
     * Initializes the RagEncryptionClient with encryption keys.
     * @param {Buffer} encryptionKey - Raw encryption key bytes.
     * @param {number} approximationFactor - Approximation factor for vector encryption.
     */
    constructor(encryptionKey, approximationFactor = 1.0) {
        if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length < 32) {
            throw new InvalidInputError("Encryption key must be a Buffer of at least 32 bytes.");
        }
        if (typeof approximationFactor !== 'number') {
            throw new InvalidInputError("Approximation factor must be a number.");
        }

        this.vectorEncryptionKey = new VectorEncryptionKey(
            new ScalingFactor(approximationFactor),
            new EncryptionKey(encryptionKey)
        );
        this.textEncryptionKey = new EncryptionKey(encryptionKey);
        this.deterministicEncryptionKey = new EncryptionKey(encryptionKey);
        this.approximationFactor = approximationFactor;
    }

    /**
     * Encrypts a vector embedding.
     * @param {Array<number>} plaintextVector - The plaintext vector to encrypt.
     * @returns {Object} - Encrypted vector and metadata.
     */
    encryptVector(plaintextVector) {
        if (!Array.isArray(plaintextVector) || !plaintextVector.every((x) => typeof x === 'number')) {
            throw new InvalidInputError("Plaintext vector must be an array of numbers.");
        }

        // Shuffle the plaintext vector
        const shuffledVector = shuffle(this.textEncryptionKey, plaintextVector);

        // Encrypt the shuffled vector
        const encryptResult = encryptVector(
            this.vectorEncryptionKey,
            this.approximationFactor,
            shuffledVector
        );

        // Generate metadata
        const keyIdHeader = new KeyIdHeader(1, "Standalone", "VectorMetadata");
        const metadata = encodeVectorMetadata(keyIdHeader, encryptResult.iv, encryptResult.authHash);

        return {
            encryptedVector: encryptResult.ciphertext,
            metadata
        };
    }

    /**
     * Decrypts an encrypted vector embedding.
     * @param {Array<number>} encryptedVector - The encrypted vector.
     * @param {Buffer} metadata - The metadata associated with the encrypted vector.
     * @returns {Array<number>} - The decrypted plaintext vector.
     */
    decryptVector(encryptedVector, metadata) {
        if (!Array.isArray(encryptedVector) || !encryptedVector.every((x) => typeof x === 'number')) {
            throw new InvalidInputError("Encrypted vector must be an array of numbers.");
        }
        if (!Buffer.isBuffer(metadata)) {
            throw new InvalidInputError("Metadata must be a Buffer.");
        }

        /// Decode metadata
        const { keyIdHeader, remainingBytes } = decodeVersionPrefixedValue(metadata);
        const iv = remainingBytes.subarray(0, 12);
        const authHashBytes = remainingBytes.subarray(12);

        // Convert the Buffer to an AuthHash object
        const authHash = new AuthHash(authHashBytes);

        // Decrypt the vector
        const shuffledVector = decryptVector(
            this.vectorEncryptionKey,
            this.approximationFactor,
            {
                ciphertext: encryptedVector,
                iv,
                authHash
            }
        );

        // Unshuffle the vector
        return unshuffle(this.textEncryptionKey, shuffledVector);
    }

    /**
     * Encrypts a text string using AES-GCM.
     * @param {string} plaintext - The plaintext string to encrypt.
     * @returns {Object} - Encrypted text, IV, and authentication tag.
     */
    encryptText(plaintext) {
        if (typeof plaintext !== 'string') {
            throw new InvalidInputError("Plaintext must be a string.");
        }
    
        // Ensure the key is exactly 32 bytes
        const key = this.textEncryptionKey.getBytes().slice(0, 32);
        
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
    
        return { ciphertext, iv, tag };
    }

    /**
     * Decrypts an AES-GCM encrypted text.
     * @param {Buffer} ciphertext - The encrypted text.
     * @param {Buffer} iv - The initialization vector.
     * @param {Buffer} tag - The authentication tag.
     * @returns {string} - The decrypted plaintext string.
     */
    decryptText(ciphertext, iv, tag) {
        if (!Buffer.isBuffer(ciphertext) || !Buffer.isBuffer(iv) || !Buffer.isBuffer(tag)) {
            throw new InvalidInputError("Ciphertext, IV, and tag must be Buffers.");
        }
    
        // Ensure the key is exactly 32 bytes
        const key = this.textEncryptionKey.getBytes().slice(0, 32);
        
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    
        return plaintext.toString('utf8');
    }

    /**
     * Encrypts text deterministically using AES-GCM-SIV.
     * Note: The SHA-256 hash is used here to generate a deterministic IV for encryption,
     * not for password hashing. This is acceptable for this specific use case.
     * @param {string} plaintext - The plaintext string to encrypt.
     * @returns {Buffer} - The encrypted text.
    */
    encryptDeterministicText(plaintext) {
        if (typeof plaintext !== 'string') {
            throw new InvalidInputError("Plaintext must be a string.");
        }
    
        // Ensure the key is exactly 32 bytes
        const key = this.deterministicEncryptionKey.getBytes().slice(0, 32);
        
        const iv = crypto.createHash('sha256').update(plaintext).digest().slice(0, 12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    
        return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]);
    }

    /**
     * Decrypts deterministically encrypted text.
     * @param {Buffer} encryptedData - The encrypted text.
     * @returns {string} - The decrypted plaintext string.
     */
    decryptDeterministicText(encryptedData) {
        if (!Buffer.isBuffer(encryptedData)) {
            throw new InvalidInputError("Encrypted data must be a Buffer.");
        }
    
        // Ensure the key is exactly 32 bytes
        const key = this.deterministicEncryptionKey.getBytes().slice(0, 32);
        
        const iv = encryptedData.slice(0, 12);
        const ciphertext = encryptedData.slice(12, -16);
        const tag = encryptedData.slice(-16);
    
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    
        return plaintext.toString('utf8');
    }
}

export { RagEncryptionClient };