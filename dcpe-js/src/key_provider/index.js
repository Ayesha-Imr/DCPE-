import { ScalingFactor, EncryptionKey, VectorEncryptionKey } from '../keys/index.js';
/**
 * Abstract KeyProvider class for managing cryptographic keys.
 */
class KeyProvider {
    /**
     * Retrieves a key from the provider.
     * @param {string} [keyId] - The identifier for the key to retrieve.
     * @returns {Promise<Buffer>} - The raw key material as a Buffer.
     * @throws {Error} - If the key is not found or cannot be accessed.
     */
    async getKey(keyId) {
        throw new Error("getKey method must be implemented by subclasses");
    }


    /**
     * Stores a key in the provider.
     * @param {Buffer} keyMaterial - The raw key to store.
     * @param {string} [keyId] - Optional identifier for the key.
     * @returns {Promise<string>} - The identifier assigned to the stored key.
     * @throws {Error} - If the key cannot be stored.
     */
    async storeKey(keyMaterial, keyId) {
        throw new Error("storeKey method must be implemented by subclasses");
    }
}


/**
 * ClientKeyProvider class for managing keys in an in-memory store (e.g., Zustand).
 */
class ClientKeyProvider extends KeyProvider {
    /**
     * @param {Object} keyStore - The in-memory key store (e.g., Zustand store).
     */
    constructor(keyStore) {
        super();
        if (typeof keyStore !== "object" || keyStore === null) {
            throw new TypeError("keyStore must be a valid object");
        }
        this.keyStore = keyStore;
    }


    /**
     * Retrieves a key from the in-memory store.
     * @param {string} [keyId] - The identifier for the key to retrieve.
     * @returns {Promise<Buffer>} - The raw key material as a Buffer.
     * @throws {Error} - If the key is not found.
     */
    async getKey(keyId) {
        const key = this.keyStore[keyId || "default"];
        if (!key) {
            throw new Error(`Key not found: ${keyId || "default"}`);
        }
        return Buffer.from(key, "base64");
    }


    /**
     * Stores a key in the in-memory store.
     * @param {Buffer} keyMaterial - The raw key to store.
     * @param {string} [keyId] - Optional identifier for the key.
     * @returns {Promise<string>} - The identifier assigned to the stored key.
     */
    async storeKey(keyMaterial, keyId) {
        const actualKeyId = keyId || "default";
        this.keyStore[actualKeyId] = keyMaterial.toString("base64");
        return actualKeyId;
    }
}


/**
 * LocalKeyProvider for managing keys locally
 * This provider stores keys in memory only for the lifetime of the instance
 */
class LocalKeyProvider extends KeyProvider {
    /**
     * @param {Object} config - Configuration options
     */
    constructor(config = {}) {
        super();
        this.keys = {};
        this.currentKey = null;
    }


    /**
     * Retrieves a key from the local store
     * @param {string} [keyId] - The identifier for the key to retrieve
     * @returns {Promise<Buffer>} - The raw key material as a Buffer
     * @throws {Error} - If the key is not found
     */
    async getKey(keyId) {
        const key = this.keys[keyId || "default"] || this.currentKey;
        if (!key) {
            throw new Error(`Key not found: ${keyId || "default"}`);
        }
        return key;
    }


    /**
     * Stores a key in the local store
     * @param {Buffer} keyMaterial - The raw key to store
     * @param {string} [keyId] - Optional identifier for the key
     * @returns {Promise<string>} - The identifier assigned to the stored key
     */
    async storeKey(keyMaterial, keyId) {
        const actualKeyId = keyId || "default";
        this.keys[actualKeyId] = keyMaterial;
        return actualKeyId;
    }


    /**
     * Sets the encryption keys
     * @param {Object|Buffer} encryptionKeys - Encryption keys to set
     */
    setKeys(encryptionKeys) {
        if (Buffer.isBuffer(encryptionKeys)) {
            this.currentKey = encryptionKeys;
        } else if (encryptionKeys && encryptionKeys instanceof VectorEncryptionKey) {
            // Preserve VectorEncryptionKey instance directly
            this.currentKey = encryptionKeys;
        } else if (encryptionKeys && typeof encryptionKeys === 'object') {
            // Handle objects that might be serialized VectorEncryptionKey
            if (encryptionKeys.scalingFactor && encryptionKeys.key) {
                // Attempt to reconstruct a VectorEncryptionKey
                const scalingFactor = new ScalingFactor(
                    encryptionKeys.scalingFactor.factor || encryptionKeys.scalingFactor
                );
                const key = new EncryptionKey(
                    Buffer.isBuffer(encryptionKeys.key.keyBytes)
                        ? encryptionKeys.key.keyBytes
                        : Buffer.from(encryptionKeys.key.keyBytes || encryptionKeys.key)
                );
                this.currentKey = new VectorEncryptionKey(scalingFactor, key);
            } else {
                // Fallback to previous behavior
                this.currentKey = encryptionKeys.key || encryptionKeys;
            }
        } else {
            throw new TypeError("Invalid encryption keys format");
        }
    }


    /**
     * Gets the current encryption keys
     * @returns {Buffer} - The raw key material
     */
    getKeys() {
        if (!this.currentKey) {
            throw new Error("No encryption keys have been set");
        }
        return this.currentKey;
    }
}


export { KeyProvider, ClientKeyProvider, LocalKeyProvider };
