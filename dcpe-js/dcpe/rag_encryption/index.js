import { encryptVector, decryptVector, shuffle, unshuffle, computeAuthHash, AuthHash } from '../crypto/index.js';
import { KeyIdHeader, encodeVectorMetadata, decodeVersionPrefixedValue } from '../headers/index.js';
import { VectorEncryptionKey, EncryptionKey, ScalingFactor } from '../keys/index.js';
import { InvalidInputError, DecryptError } from '../exceptions/index.js';
import crypto from 'crypto';
import { hkdf } from '../crypto/hkdf.js';

/**
 * RagEncryptionClient: High-level interface for encryption and decryption.
 */
class RagEncryptionClient {
    /**
 * Initializes the RagEncryptionClient with encryption keys.
 * @param {Buffer|null} encryptionKey - Raw encryption key bytes.
 * @param {number} approximationFactor - Approximation factor for vector encryption.
 * @param {KeyProvider} keyProvider - Optional key provider implementation.
 * @param {string} keyId - Optional key identifier to use with the key provider.
 * @param {boolean} _skipValidation - Internal flag to skip validation (used by create method).
 */
constructor(encryptionKey = null, approximationFactor = 1.0, keyProvider = null, keyId = null, _skipValidation = false) {
    // Skip validation if internal flag is set (used by create method)
    if (_skipValidation) {
        return;
    }
    
    // For direct key initialization only - use static create() for key provider
    if (keyProvider || keyId) {
        throw new InvalidInputError("For async key provider initialization, use the static create() method");
    }
    
    if (!encryptionKey) {
        throw new InvalidInputError("Encryption key must be provided when using constructor directly");
    }
    
    this._initializeWithKey(encryptionKey, approximationFactor);
}

/**
 * Creates an instance of RagEncryptionClient.
 */
static async create(encryptionKey = null, approximationFactor = 1.0, keyProvider = null, keyId = null) {
    // Create a new instance with validation skipped
    const client = new RagEncryptionClient(null, 1.0, null, null, true);
    
    if (keyProvider && keyId) {
        // Rest remains the same...
            // Check for the getKey method instead of instanceof
            if (typeof keyProvider.getKey !== 'function') {
                throw new TypeError("keyProvider must have a getKey method");
            }
            await client._initializeWithKeyProvider(keyProvider, keyId, approximationFactor);
        } else if (encryptionKey) {
            client._initializeWithKey(encryptionKey, approximationFactor);
        } else {
            throw new InvalidInputError("Either encryptionKey or (keyProvider and keyId) must be provided");
        }
        return client;
    }

    /**
     * Initialize client with direct key material
     * @private
     */
    _initializeWithKey(encryptionKey, approximationFactor) {
        if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length < 32) {
            throw new InvalidInputError("Encryption key must be a Buffer of at least 32 bytes");
        }
        if (typeof approximationFactor !== 'number') {
            throw new InvalidInputError("Approximation factor must be a number");
        }

        this.vectorEncryptionKey = new VectorEncryptionKey(
            new ScalingFactor(approximationFactor),
            new EncryptionKey(encryptionKey)
        );
        this.textEncryptionKey = new EncryptionKey(encryptionKey);
        this.deterministicEncryptionKey = new EncryptionKey(encryptionKey);
        this.approximationFactor = approximationFactor;
        this.keyId = "local-key";
        this.keyProvider = null;
    }

    /**
     * Initialize client with key provider
     * @private
     */
    async _initializeWithKeyProvider(keyProvider, keyId, approximationFactor) {
        try {
            const encryptionKey = await keyProvider.getKey(keyId);
            this._initializeWithKey(encryptionKey, approximationFactor);
            this.keyId = keyId;
            this.keyProvider = keyProvider;
        } catch (error) {
            throw new InvalidInputError(`Failed to get key from provider: ${error.message}`);
        }
    }

    // Update rotateKey to support key provider
    /**
     * Rotate to a new encryption key.
     * @param {Buffer} newKeyMaterial - New raw encryption key bytes (optional if using key provider).
     * @param {string} newKeyId - New key identifier to use with the current key provider (optional).
     */
    async rotateKey(newKeyMaterial = null, newKeyId = null) {
        // Store old keys for reference
        this._oldVectorEncryptionKey = this.vectorEncryptionKey;
        this._oldTextEncryptionKey = this.textEncryptionKey;
        this._oldDeterministicEncryptionKey = this.deterministicEncryptionKey;
        
        // Get new key material
        let newKey;
        if (this.keyProvider && newKeyId) {
            // Get from provider if available
            try {
                newKey = await this.keyProvider.getKey(newKeyId);
                this.keyId = newKeyId;
            } catch (error) {
                throw new InvalidInputError(`Failed to get new key from provider: ${error.message}`);
            }
        } else if (newKeyMaterial) {
            // Use directly provided material
            if (!Buffer.isBuffer(newKeyMaterial) || newKeyMaterial.length < 32) {
                throw new InvalidInputError("New key material must be a Buffer of at least 32 bytes");
            }
            newKey = newKeyMaterial;
        } else {
            throw new InvalidInputError("Either newKeyMaterial or newKeyId must be provided");
        }
        
        // Update current keys with new material
        this.vectorEncryptionKey = new VectorEncryptionKey(
            new ScalingFactor(this.approximationFactor),
            new EncryptionKey(newKey)
        );
        this.textEncryptionKey = new EncryptionKey(newKey);
        this.deterministicEncryptionKey = new EncryptionKey(newKey);
    }


    /**
     * Encrypts a vector embedding.
     * @param {Array<number>} plaintextVector - The plaintext vector to encrypt.
     * @returns {[Array<number>, Buffer]} - A tuple containing the encrypted vector and metadata.
     */
    encryptVector(plaintextVector) {
        if (!Array.isArray(plaintextVector) || !plaintextVector.every((x) => typeof x === 'number')) {
            throw new InvalidInputError("Plaintext vector must be an array of numbers");
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
        const keyIdHeader = new KeyIdHeader(
            (typeof this.keyId === 'string' ? this.keyId.split('').reduce((a, c) => a + c.charCodeAt(0), 0) : 1) % 9999,
            "Standalone",
            "VectorMetadata"
        );
        const metadata = encodeVectorMetadata(keyIdHeader, encryptResult.iv, encryptResult.authHash);

        // Return tuple format like Python
        return [encryptResult.ciphertext, metadata];
    }

    /**
     * Decrypts an encrypted vector embedding.
     * @param {Array<number>} encryptedVector - The encrypted vector.
     * @param {Buffer} pairedIclInfo - The metadata associated with the encrypted vector.
     * @returns {Array<number>} - The decrypted plaintext vector.
     */
    decryptVector(encryptedVector, pairedIclInfo) {
        if (!Array.isArray(encryptedVector) || !encryptedVector.every((x) => typeof x === 'number')) {
            throw new InvalidInputError("Encrypted vector must be an array of numbers");
        }
        if (!Buffer.isBuffer(pairedIclInfo)) {
            throw new InvalidInputError("Metadata must be a Buffer");
        }

        /// Decode metadata
        const { keyIdHeader, remainingBytes } = decodeVersionPrefixedValue(pairedIclInfo);
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
        const key = this.textEncryptionKey.getBytes().subarray(0, 32);
        
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
        const key = this.textEncryptionKey.getBytes().subarray(0, 32);
        
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    
        return plaintext.toString('utf8');
    }

    /**
     * Encrypts text deterministically using AES-GCM, mirroring Python implementation
     * with HKDF key derivation and deterministic nonce generation.
     * @param {string} plaintext - The plaintext string to encrypt.
     * @returns {Buffer} - The encrypted text with metadata.
     */
    encryptDeterministicText(plaintext) {
        if (typeof plaintext !== 'string') {
            throw new InvalidInputError("Plaintext must be a string");
        }

        // 1. Derive key using HKDF similarly to Python implementation
        const salt = Buffer.from('DCPE-Deterministic');
        const info = Buffer.from('deterministic_encryption_key');
        const derivedKey = hkdf(
            this.deterministicEncryptionKey.getBytes(),
            32,
            salt,
            info
        );

        // 2. Create deterministic nonce using HMAC from plaintext
        const hmac = crypto.createHmac('sha256', derivedKey);
        hmac.update(Buffer.from(plaintext, 'utf8'));
        const deterministicNonce = hmac.digest().subarray(0, 12);

        // 3. Encrypt with AES-GCM using the derived key and deterministic nonce
        const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, deterministicNonce);
        const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();

        // 4. Match Python's output format: nonce + ciphertext + tag
        return Buffer.concat([deterministicNonce, ciphertext, tag]);
    }

    /**
     * Decrypts deterministically encrypted text, matching Python implementation.
     * @param {Buffer} encryptedData - The encrypted text.
     * @returns {string} - The decrypted plaintext string.
     */
    decryptDeterministicText(encryptedData) {
        if (!Buffer.isBuffer(encryptedData)) {
            throw new InvalidInputError("Encrypted data must be a Buffer");
        }

        if (encryptedData.length < 28) { // 12 (nonce) + 16 (min tag size)
            throw new InvalidInputError("Encrypted data too short");
        }

        // 1. Split components: nonce + ciphertext + tag
        const nonce = encryptedData.subarray(0, 12);
        const ciphertext = encryptedData.subarray(12, encryptedData.length - 16);
        const tag = encryptedData.subarray(encryptedData.length - 16);

        // 2. Derive the same key used for encryption
        const salt = Buffer.from('DCPE-Deterministic');
        const info = Buffer.from('deterministic_encryption_key');
        const derivedKey = hkdf(
            this.deterministicEncryptionKey.getBytes(),
            32,
            salt,
            info
        );

        // 3. Decrypt with AES-GCM
        try {
            const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, nonce);
            decipher.setAuthTag(tag);
            const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
            return plaintext.toString('utf8');
        } catch (e) {
            throw new DecryptError(`Deterministic text decryption failed: ${e.message}`);
        }
    }

}

export { RagEncryptionClient };