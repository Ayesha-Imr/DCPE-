/**
 * Main DCPE class providing a simple interface to the library's functionality.
 * This class serves as the primary entry point for the DCPE library and handles
 * key management, vector encryption/decryption, text encryption/decryption, and
 * metadata encryption/decryption.
 *
 * @example
 * ```javascript
 * // Create a DCPE instance with default configuration
 * const dcpe = new DCPE();
 *
 * // Generate encryption keys
 * const keys = await dcpe.generateKeys();
 * dcpe.setKeys(keys);
 *
 * // Encrypt a vector
 * const vector = [0.1, 0.2, 0.3, 0.4];
 * const encryptedVector = dcpe.encryptVector(vector);
 * ```
 */
import * as crypto from './crypto/index.js';
import * as ragEncryption from './rag_encryption/index.js';
import * as keyProvider from './key_provider/index.js';
import * as keys from './keys/index.js';


class DCPE {
  /**
   * Create a new DCPE instance
   * @param {Object} config - Configuration options
   * @param {string} [config.keyProvider='local'] - Key provider type ('local', 'vault', etc.)
   * @param {Object} [config.keyProviderConfig={}] - Configuration options for the key provider
   * @param {Object} [config.vectorConfig={}] - Configuration options for vector operations
   *  
   * @example
   * ```javascript
   * // Create with default configuration (local key provider)
   * const dcpeDefault = new DCPE();
   *
   * // Create with custom configuration
   * const dcpeCustom = new DCPE({
   *   keyProvider: 'local',
   *   vectorConfig: { approximationFactor: 0.95 }
   * });
   * ```
   */
  constructor(config = {}) {
    this.config = {
      // Default configuration
      keyProvider: 'local',
      keyProviderConfig: {},
      vectorConfig: {},
      ...config
    };
   
    this.keyProvider = null;
    this._initialize();
  }


  /**
   * Initialize the DCPE instance
   * @private
   */
  _initialize() {
    // Initialize key provider
    this._initializeKeyProvider();
  }


  /**
   * Initialize the key provider based on configuration
   * @private
   * @throws {Error} If the specified key provider type is not supported
   */
  _initializeKeyProvider() {
    const { keyProvider: providerType, keyProviderConfig } = this.config;
   
    switch (providerType.toLowerCase()) {
      case 'local':
        this.keyProvider = new keyProvider.LocalKeyProvider(keyProviderConfig);
        break;
      // Add other key providers as needed
      default:
        throw new Error(`Unsupported key provider: ${providerType}`);
    }
  }


  /**
   * Generate encryption keys for use with the DCPE library
   * @param {Object} options - Options for key generation
   * @param {number} [options.approximationFactor=1.0] - Approximation factor for vector encryption (1.0 = exact, lower values = faster but less accurate)
   * @returns {Promise<Buffer>} - Generated encryption key material that can be set using setKeys()
   *
   * @example
   * ```javascript
   * const keys = await dcpe.generateKeys({ approximationFactor: 0.95 });
   * dcpe.setKeys(keys);
   * ```
   */
  async generateKeys(options = {}) {
    return await keys.generateEncryptionKeys(options);
  }


  /**
   * Set encryption keys for the DCPE instance
   * @param {Buffer|Object} encryptionKeys - Encryption keys to set
   * @throws {TypeError} If encryption keys are in an invalid format
   *
   * @example
   * ```javascript
   * // Generate and set keys
   * const keys = await dcpe.generateKeys();
   * dcpe.setKeys(keys);
   *
   * // Set existing keys
   * const existingKeys = loadKeysFromSecureStorage();
   * dcpe.setKeys(existingKeys);
   * ```
   */
  setKeys(encryptionKeys) {
    this.keyProvider.setKeys(encryptionKeys);
  }


  /**
   * Encrypt a vector using DCPE (Distance Comparison Preserving Encryption)
   * This preserves the relative distances between vectors so similarity search
   * still works on the encrypted vectors.
   *
   * @param {Array<number>} vector - Vector to encrypt
   * @param {Object} options - Encryption options
   * @returns {Array<number>} - Encrypted vector that can be stored in a vector database
   * @throws {Error} If encryption fails or keys are not set
   *
   * @example
   * ```javascript
   * const vector = [0.1, 0.2, 0.3, 0.4];
   * const encryptedVector = dcpe.encryptVector(vector);
   * // Store encryptedVector in your vector database
   * ```
   */
  encryptVector(vector, options = {}) {
    const key = this.keyProvider.getKeys();
    const approximationFactor = options.approximationFactor || this.config.vectorConfig.approximationFactor || 1.0;
   
    // Directly pass the needed parameters to the crypto function in the correct order
    const result = crypto.encryptVector(key, approximationFactor, vector);
   
    return result.ciphertext; // Return just the ciphertext for storage
  }


  /**
   * Decrypt a vector that was encrypted with DCPE
   * @param {Array<number>} encryptedVector - Encrypted vector
   * @param {Object} options - Decryption options
   * @returns {Array<number>} - Original, decrypted vector
   * @throws {Error} If decryption fails or keys are not set
   *
   * @example
   * ```javascript
   * const encryptedVector = getVectorFromDatabase();
   * const decryptedVector = dcpe.decryptVector(encryptedVector);
   * ```
   */
  decryptVector(encryptedVector, metadata, options = {}) {
    const key = this.keyProvider.getKeys();
    const approximationFactor = options.approximationFactor || this.config.vectorConfig.approximationFactor || 1.0;
   
    // Create the encryptedResult object expected by the crypto function
    const encryptedResult = {
      ciphertext: encryptedVector,
      iv: metadata.iv,
      authHash: metadata.authHash
    };
   
    return crypto.decryptVector(key, approximationFactor, encryptedResult);
  }


  /**
   * Encrypt text using AES-GCM encryption
   * @param {string} text - Text to encrypt
   * @param {Object} options - Encryption options
   * @returns {Object} - Encrypted text object containing ciphertext, iv, and tag
   * @throws {Error} If encryption fails or keys are not set
   *
   * @example
   * ```javascript
   * const text = "This is sensitive information";
   * const encryptedText = dcpe.encryptText(text);
   * // encryptedText contains { ciphertext, iv, tag } that can be stored
   * ```
   */
  encryptText(text, options = {}) {
    const keys = this.keyProvider.getKeys();
    return ragEncryption.encryptText(text, keys, options);
  }


  /**
   * Decrypt text that was encrypted with AES-GCM
   * @param {Object} encryptedText - Encrypted text object containing ciphertext, iv, and tag
   * @param {Object} options - Decryption options
   * @returns {string} - Original, decrypted text
   * @throws {Error} If decryption fails or keys are not set
   *
   * @example
   * ```javascript
   * const encryptedText = getFromDatabase();
   * const plaintext = dcpe.decryptText(encryptedText);
   * ```
   */
  decryptText(encryptedText, options = {}) {
    const keys = this.keyProvider.getKeys();
    return ragEncryption.decryptText(encryptedText, keys, options);
  }


  /**
   * Encrypt metadata field using deterministic encryption
   * This allows for exact-match filtering on encrypted fields
   *
   * @param {string|number} value - Value to encrypt
   * @param {Object} options - Encryption options
   * @returns {Buffer} - Deterministically encrypted value that can be used for filtering
   * @throws {Error} If encryption fails or keys are not set
   *
   * @example
   * ```javascript
   * const category = "finance";
   * const encryptedCategory = dcpe.encryptMetadata(category);
   * // Store with vector: { vector: encryptedVector, metadata: { category: encryptedCategory } }
   * ```
   */
  encryptMetadata(value, options = {}) {
    const keys = this.keyProvider.getKeys();
    return ragEncryption.encryptMetadataField(value, keys, options);
  }


  /**
   * Decrypt metadata field that was encrypted with deterministic encryption
   * @param {Buffer} encryptedValue - Encrypted value
   * @param {Object} options - Decryption options
   * @returns {string|number} - Original, decrypted value
   * @throws {Error} If decryption fails or keys are not set
   *
   * @example
   * ```javascript
   * const encryptedCategory = result.metadata.category;
   * const category = dcpe.decryptMetadata(encryptedCategory);
   * ```
   */
  decryptMetadata(encryptedValue, options = {}) {
    const keys = this.keyProvider.getKeys();
    return ragEncryption.decryptMetadataField(encryptedValue, keys, options);
  }
}


export default DCPE;
