import crypto from 'crypto';
import { create, all } from 'mathjs';

// Base class for all exceptions
class DCPEError extends Error {
  /**
   * Initializes the base error with a default or provided message.
   * @param {string} message - The error message.
   */
  constructor() {
    let message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "An error occurred in the SDK";
    super(message);
    this.name = "DCPEError";
  }
}

// Error while loading or with invalid configuration
class InvalidConfigurationError extends DCPEError {
  constructor() {
    let message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "Invalid configuration";
    super(`InvalidConfigurationError: ${message}`);
    this.name = "InvalidConfigurationError";
  }
}

// Error with key used for encryption or decryption
class InvalidKeyError extends DCPEError {
  constructor() {
    let message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "Invalid key";
    super(`InvalidKeyError: ${message}`);
    this.name = "InvalidKeyError";
  }
}

// Error with user-provided input data
class InvalidInputError extends DCPEError {
  constructor() {
    let message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "Invalid input";
    super(`InvalidInputError: ${message}`);
    this.name = "InvalidInputError";
  }
}

// Base class for encryption-related errors
class EncryptError extends DCPEError {
  constructor() {
    let message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "Encryption error";
    super(`EncryptError: ${message}`);
    this.name = "EncryptError";
  }
}

// Base class for decryption-related errors
class DecryptError extends DCPEError {
  constructor() {
    let message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "Decryption error";
    super(`DecryptError: ${message}`);
    this.name = "DecryptError";
  }
}

// Errors specific to vector encryption
class VectorEncryptError extends EncryptError {
  constructor() {
    let message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "Vector encryption error";
    super(message);
    this.name = "VectorEncryptError";
    this.message = `VectorEncryptError: ${message.replace(/^VectorEncryptError: /, '')}`;
  }
}

// Errors specific to vector decryption
class VectorDecryptError extends DecryptError {
  constructor() {
    let message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "Vector decryption error";
    super(message);
    this.name = "VectorDecryptError";
    this.message = `VectorDecryptError: ${message.replace(/^VectorDecryptError: /, '')}`;
  }
}

// Error due to numerical overflow during encryption
class OverflowError extends EncryptError {
  constructor() {
    let message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "Embedding or approximation factor too large";
    super(message);
    this.name = "OverflowError";
    this.message = `OverflowError: ${message.replace(/^OverflowError: /, '')}`;
  }
}

// Error during Protobuf serialization or deserialization
class ProtobufError extends DCPEError {
  constructor() {
    let message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "Protobuf error";
    super(`ProtobufError: ${message}`);
    this.name = "ProtobufError";
  }
}

// Error during a request to an external service (like TSP)
class RequestError extends DCPEError {
  constructor() {
    let message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "Request error";
    super(`RequestError: ${message}`);
    this.name = "RequestError";
  }
}

// Error during JSON serialization or deserialization
class SerdeJsonError extends DCPEError {
  constructor() {
    let message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "Serde JSON error";
    super(`SerdeJsonError: ${message}`);
    this.name = "SerdeJsonError";
  }
}

// Error directly from the Tenant Security Proxy (TSP)
/**
 * Represents a TSP (Third-Party Service Provider) error.
 * This error extends the DCPEError class and includes additional
 * details specific to TSP-related issues.
 *
 * @class
 * @extends DCPEError
 * 
 * @param {string} errorVariant - The error variant, typically a string representation
 *                                that categorizes the type of error.
 * @param {number} httpCode - The HTTP status code associated with the error.
 * @param {number} tspCode - The TSP-specific error code providing additional context.
 * @param {string} [message="TSP error"] - A descriptive error message.
 */
class TspError extends DCPEError {
  /**
   * Initializes the TSP error with specific details.
   * @param {string} errorVariant - The error variant (e.g., string representation).
   * @param {number} httpCode - The HTTP status code.
   * @param {number} tspCode - The TSP-specific error code.
   * @param {string} message - The error message.
   */
  constructor(errorVariant, httpCode, tspCode) {
    let message = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : "TSP error";
    super(`TspError: ${message}, Variant: '${errorVariant}', HTTP Code: ${httpCode}, TSP Code: ${tspCode}`);
    this.name = "TspError";
    this.errorVariant = errorVariant;
    this.httpCode = httpCode;
    this.tspCode = tspCode;
  }
}

var index$5 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    DCPEError: DCPEError,
    DecryptError: DecryptError,
    EncryptError: EncryptError,
    InvalidConfigurationError: InvalidConfigurationError,
    InvalidInputError: InvalidInputError,
    InvalidKeyError: InvalidKeyError,
    OverflowError: OverflowError,
    ProtobufError: ProtobufError,
    RequestError: RequestError,
    SerdeJsonError: SerdeJsonError,
    TspError: TspError,
    VectorDecryptError: VectorDecryptError,
    VectorEncryptError: VectorEncryptError
});

/**
 * Represents a raw encryption key as bytes.
 */
class EncryptionKey {
  /**
   * @param {Buffer} keyBytes - The raw encryption key as a Buffer.
   */
  constructor(keyBytes) {
    if (!Buffer.isBuffer(keyBytes)) {
      throw new TypeError('EncryptionKey must be initialized with a Buffer');
    }
    this.keyBytes = keyBytes;
  }

  /**
   * Returns the raw key bytes.
   * @returns {Buffer}
   */
  getBytes() {
    return this.keyBytes;
  }

  /**
   * Checks equality with another EncryptionKey.
   * @param {EncryptionKey} other
   * @returns {boolean}
   */
  equals(other) {
    return other instanceof EncryptionKey && this.keyBytes.equals(other.keyBytes);
  }

  /**
   * String representation of the EncryptionKey.
   * @returns {string}
   */
  toString() {
    return `EncryptionKey(bytes of length: ${this.keyBytes.length})`;
  }
}

/**
 * Represents the scaling factor used in vector encryption.
 */
class ScalingFactor {
  /**
   * @param {number} factor - The scaling factor as a float.
   */
  constructor(factor) {
    if (typeof factor !== 'number') {
      throw new TypeError('ScalingFactor must be initialized with a number');
    }
    this.factor = factor;
  }

  /**
   * Returns the scaling factor value.
   * @returns {number}
   */
  getFactor() {
    return this.factor;
  }

  /**
   * Checks equality with another ScalingFactor.
   * @param {ScalingFactor} other
   * @returns {boolean}
   */
  equals(other) {
    return other instanceof ScalingFactor && this.factor === other.factor;
  }

  /**
   * String representation of the ScalingFactor.
   * @returns {string}
   */
  toString() {
    return `ScalingFactor(factor: ${this.factor})`;
  }
}

/**
 * Represents the combined key for vector encryption, including scaling factor and encryption key.
 */
class VectorEncryptionKey {
  /**
   * @param {ScalingFactor} scalingFactor - The scaling factor.
   * @param {EncryptionKey} key - The encryption key.
   */
  constructor(scalingFactor, key) {
    if (!(scalingFactor instanceof ScalingFactor)) {
      throw new TypeError('VectorEncryptionKey scalingFactor must be a ScalingFactor instance');
    }
    if (!(key instanceof EncryptionKey)) {
      throw new TypeError('VectorEncryptionKey key must be an EncryptionKey instance');
    }
    this.scalingFactor = scalingFactor;
    this.key = key;
  }

  /**
   * Derives a VectorEncryptionKey from a master secret, tenant ID, and derivation path.
   * @param {Buffer} secret - The master secret as a Buffer.
   * @param {string} tenantId - The tenant ID.
   * @param {string} derivationPath - The derivation path.
   * @returns {VectorEncryptionKey}
   */
  static deriveFromSecret(secret, tenantId, derivationPath) {
    if (!Buffer.isBuffer(secret)) {
      throw new TypeError('Secret must be a Buffer');
    }
    if (typeof tenantId !== 'string') {
      throw new TypeError('Tenant ID must be a string');
    }
    if (typeof derivationPath !== 'string') {
      throw new TypeError('Derivation Path must be a string');
    }
    const payload = Buffer.from(`${tenantId}-${derivationPath}`, 'utf-8');
    const hashResultBytes = crypto.createHmac('sha512', secret).update(payload).digest();
    return this.unsafeBytesToKey(hashResultBytes);
  }

  /**
    * Constructs a VectorEncryptionKey from raw bytes.
    * @param {Buffer} keyBytes - The raw bytes.
    * @returns {VectorEncryptionKey}
    * @throws {InvalidKeyError} If keyBytes is not long enough.
    */
  static unsafeBytesToKey(keyBytes) {
    if (keyBytes.length < 35) {
      throw new InvalidKeyError('Key bytes must be at least 35 bytes long');
    }
    const scalingFactorBytes = keyBytes.subarray(0, 3);
    const keyMaterialBytes = keyBytes.subarray(3, 35);

    // Add leading zero byte to match Python's behavior
    const paddedBytes = Buffer.concat([Buffer.from([0]), scalingFactorBytes]);

    // Use readUInt32BE instead of parseInt for consistent binary representation
    const scalingFactorU32 = paddedBytes.readUInt32BE(0);
    const scalingFactor = new ScalingFactor(scalingFactorU32);
    const encryptionKey = new EncryptionKey(keyMaterialBytes);
    return new VectorEncryptionKey(scalingFactor, encryptionKey);
  }

  /**
   * Checks equality with another VectorEncryptionKey.
   * @param {VectorEncryptionKey} other
   * @returns {boolean}
   */
  equals(other) {
    return other instanceof VectorEncryptionKey && this.scalingFactor.equals(other.scalingFactor) && this.key.equals(other.key);
  }

  /**
   * String representation of the VectorEncryptionKey.
   * @returns {string}
   */
  toString() {
    return `VectorEncryptionKey(scalingFactor=${this.scalingFactor}, key=${this.key})`;
  }
}

/**
 * Generates a cryptographically random EncryptionKey (32 bytes).
 * @returns {EncryptionKey}
 */
function generateRandomKey() {
  return new EncryptionKey(crypto.randomBytes(32));
}

/**
 * Generates encryption keys for use with DCPE
 * @param {Object} options - Options for key generation
 * @param {number} [options.approximationFactor=1.0] - Approximation factor for vector encryption
 * @returns {Promise<Buffer>} - Generated encryption key material
 */
async function generateEncryptionKeys() {
  // Generate a random key for encryption
  return crypto.randomBytes(32);
}

var index$4 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    EncryptionKey: EncryptionKey,
    ScalingFactor: ScalingFactor,
    VectorEncryptionKey: VectorEncryptionKey,
    generateEncryptionKeys: generateEncryptionKeys,
    generateRandomKey: generateRandomKey
});

const math = create(all);

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
  return Array.from({
    length: dimensionality
  }, () => {
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
  const radius = scalingFactor.getFactor() / 4 * approximationFactor;
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
  return vector.map(val => val * scale / norm);
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
  return function () {
    const hmac = crypto.createHmac('sha256', key.getBytes());
    hmac.update(Buffer.from([this.counter++ & 0xFF]));
    const bytes = hmac.digest();
    return bytes.readUInt32LE(0) / 0x100000000;
  }.bind({
    counter: 0
  });
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
  return indices.map(index => inputArray[index]);
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
  const indices = Array.from({
    length: shuffledArray.length
  }, (_, i) => i);
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
  encryptedVector.forEach(val => {
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
  if (!ciphertext.every(val => Number.isFinite(val))) {
    throw new Error("Overflow error: Embedding or approximation factor too large.");
  }
  const authHash = computeAuthHash(key, approximationFactor, iv, ciphertext);
  return {
    ciphertext,
    iv,
    authHash
  };
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
  const {
    ciphertext,
    iv,
    authHash
  } = encryptedResult;
  if (!computeAuthHash(key, approximationFactor, iv, ciphertext).equals(authHash)) {
    throw new DecryptError("Authentication hash mismatch");
  }
  const noiseVector = generateNoiseVector(key, iv, approximationFactor, ciphertext.length);
  return ciphertext.map((val, i) => (val - noiseVector[i]) / key.scalingFactor.getFactor());
}

var index$3 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    AuthHash: AuthHash,
    computeAuthHash: computeAuthHash,
    decryptVector: decryptVector,
    encryptVector: encryptVector,
    generateNoiseVector: generateNoiseVector,
    sampleNormalVector: sampleNormalVector,
    sampleUniformPoint: sampleUniformPoint,
    shuffle: shuffle,
    unshuffle: unshuffle
});

/**
 * Enumeration for EDEK Types
 */
const EdekType = Object.freeze({
  STANDALONE: "Standalone",
  SAAS_SHIELD: "SaasShield",
  DATA_CONTROL_PLATFORM: "DataControlPlatform"
});

/**
 * Enumeration for Payload Types
 */
const PayloadType = Object.freeze({
  DETERMINISTIC_FIELD: "DeterministicField",
  VECTOR_METADATA: "VectorMetadata",
  STANDARD_EDEK: "StandardEdek"
});

/**
 * Represents the Key ID Header
 */
class KeyIdHeader {
  /**
   * @param {number} keyId - The key ID (integer).
   * @param {string} edekType - The EDEK type (from EdekType).
   * @param {string} payloadType - The payload type (from PayloadType).
   */
  constructor(keyId, edekType, payloadType) {
    if (typeof keyId !== 'number') {
      throw new TypeError("keyId must be a number");
    }
    if (!Object.values(EdekType).includes(edekType)) {
      throw new TypeError("edekType must be a valid EdekType value");
    }
    if (!Object.values(PayloadType).includes(payloadType)) {
      throw new TypeError("payloadType must be a valid PayloadType value");
    }
    this.keyId = keyId;
    this.edekType = edekType;
    this.payloadType = payloadType;
  }

  /**
   * Creates a KeyIdHeader instance.
   * @param {string} edekType - The EDEK type.
   * @param {string} payloadType - The payload type.
   * @param {number} keyId - The key ID.
   * @returns {KeyIdHeader}
   */
  static createHeader(edekType, payloadType, keyId) {
    return new KeyIdHeader(keyId, edekType, payloadType);
  }

  /**
   * Serializes the KeyIdHeader to bytes.
   * @returns {Buffer}
   */
  writeToBytes() {
    const buffer = Buffer.alloc(6);
    buffer.writeUInt32BE(this.keyId, 0); // Write keyId (4 bytes)
    buffer.writeUInt8(this._encodeTypeByte(), 4); // Write encoded type byte
    buffer.writeUInt8(0, 5); // Padding byte
    return buffer;
  }

  /**
   * Parses bytes and reconstructs a KeyIdHeader instance.
   * @param {Buffer} headerBytes - The serialized header bytes.
   * @returns {KeyIdHeader}
   */
  static parseFromBytes(headerBytes) {
    if (headerBytes.length !== 6) {
      throw new InvalidInputError(`Header bytes must be 6 bytes long, got ${headerBytes.length}`);
    }
    const keyId = headerBytes.readUInt32BE(0); // Read keyId (4 bytes)
    const typeByte = headerBytes.readUInt8(4); // Read type byte
    const paddingByte = headerBytes.readUInt8(5); // Read padding byte

    if (paddingByte !== 0) {
      throw new InvalidInputError(`Padding byte in header is not zero: ${paddingByte}`);
    }
    const {
      edekType,
      payloadType
    } = this._decodeTypeByte(typeByte);
    return new KeyIdHeader(keyId, edekType, payloadType);
  }

  /**
   * Encodes EDEK type and Payload type into a single byte.
   * @returns {number}
   */
  _encodeTypeByte() {
    const edekNumeric = Object.values(EdekType).indexOf(this.edekType) << 4; // Shift EDEK type to top 4 bits
    const payloadNumeric = Object.values(PayloadType).indexOf(this.payloadType); // Payload type in bottom 4 bits
    return edekNumeric | payloadNumeric;
  }

  /**
   * Decodes the type byte back to EDEK type and Payload type.
   * @param {number} typeByte - The encoded type byte.
   * @returns {{ edekType: string, payloadType: string }}
   */
  static _decodeTypeByte(typeByte) {
    const edekTypeIndex = (typeByte & 0xF0) >> 4; // Extract top 4 bits
    const payloadTypeIndex = typeByte & 0x0F; // Extract bottom 4 bits

    const edekType = Object.values(EdekType)[edekTypeIndex];
    const payloadType = Object.values(PayloadType)[payloadTypeIndex];
    if (!edekType || !payloadType) {
      throw new InvalidInputError("Invalid type byte encoding");
    }
    return {
      edekType,
      payloadType
    };
  }
}

/**
 * Represents Vector Metadata, including IV and AuthHash.
 */
class VectorMetadata {
  /**
   * @param {KeyIdHeader} keyIdHeader - The KeyIdHeader instance.
   * @param {Buffer} iv - The initialization vector.
   * @param {AuthHash} authHash - The authentication hash.
   */
  constructor(keyIdHeader, iv, authHash) {
    if (!(keyIdHeader instanceof KeyIdHeader)) {
      throw new TypeError("keyIdHeader must be an instance of KeyIdHeader");
    }
    if (!Buffer.isBuffer(iv)) {
      throw new TypeError("iv must be a Buffer");
    }
    if (!(authHash instanceof AuthHash)) {
      throw new TypeError("authHash must be an instance of AuthHash");
    }
    this.keyIdHeader = keyIdHeader;
    this.iv = iv;
    this.authHash = authHash;
  }
}

/**
 * Encodes vector metadata into bytes.
 * @param {KeyIdHeader} keyIdHeader - The KeyIdHeader instance.
 * @param {Buffer} iv - The initialization vector.
 * @param {AuthHash} authHash - The authentication hash.
 * @returns {Buffer}
 */
function encodeVectorMetadata(keyIdHeader, iv, authHash) {
  return Buffer.concat([keyIdHeader.writeToBytes(), iv, authHash.getBytes()]);
}

/**
 * Decodes a byte stream with a prefixed KeyIdHeader.
 * @param {Buffer} valueBytes - The byte stream.
 * @returns {{ keyIdHeader: KeyIdHeader, remainingBytes: Buffer }}
 */
function decodeVersionPrefixedValue(valueBytes) {
  if (valueBytes.length < 6) {
    throw new InvalidInputError("Value bytes too short to contain KeyIdHeader");
  }
  const headerBytes = valueBytes.subarray(0, 6);
  const remainingBytes = valueBytes.subarray(6);
  const keyIdHeader = KeyIdHeader.parseFromBytes(headerBytes);
  return {
    keyIdHeader,
    remainingBytes
  };
}

var index$2 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    EdekType: EdekType,
    KeyIdHeader: KeyIdHeader,
    PayloadType: PayloadType,
    VectorMetadata: VectorMetadata,
    decodeVersionPrefixedValue: decodeVersionPrefixedValue,
    encodeVectorMetadata: encodeVectorMetadata
});

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
  constructor() {
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
    } else if (encryptionKeys && typeof encryptionKeys === 'object') {
      this.currentKey = encryptionKeys.key || encryptionKeys;
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

var index$1 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    ClientKeyProvider: ClientKeyProvider,
    KeyProvider: KeyProvider,
    LocalKeyProvider: LocalKeyProvider
});

/**
 * HMAC-based Key Derivation Function implementation.
 * 
 * @param {Buffer} ikm - Input key material
 * @param {number} length - The desired length of the derived key
 * @param {Buffer} salt - Optional salt value (recommended)
 * @param {Buffer} info - Optional context and application specific information
 * @returns {Buffer} The derived key
 */
function hkdf(ikm, length, salt, info) {
  if (!Buffer.isBuffer(ikm)) {
    throw new TypeError('Input key material must be a Buffer');
  }

  // Default values
  salt = salt || Buffer.alloc(0);
  info = info || Buffer.alloc(0);

  // Step 1: Extract
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest();

  // Step 2: Expand
  const result = Buffer.alloc(length);
  let previous = Buffer.alloc(0);
  let resultPosition = 0;
  const hashLen = 32; // SHA-256 hash length

  for (let i = 1; resultPosition < length; i++) {
    const hmac = crypto.createHmac('sha256', prk);
    hmac.update(Buffer.concat([previous, info, Buffer.from([i])]));
    const next = hmac.digest();
    const remainder = Math.min(length - resultPosition, hashLen);
    next.copy(result, resultPosition, 0, remainder);
    previous = next;
    resultPosition += remainder;
  }
  return result;
}

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
  constructor() {
    let encryptionKey = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : null;
    let approximationFactor = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 1.0;
    let keyProvider = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : null;
    let keyId = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : null;
    let _skipValidation = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : false;
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
  static async create() {
    let encryptionKey = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : null;
    let approximationFactor = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 1.0;
    let keyProvider = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : null;
    let keyId = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : null;
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
    this.vectorEncryptionKey = new VectorEncryptionKey(new ScalingFactor(approximationFactor), new EncryptionKey(encryptionKey));
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
  async rotateKey() {
    let newKeyMaterial = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : null;
    let newKeyId = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : null;
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
    this.vectorEncryptionKey = new VectorEncryptionKey(new ScalingFactor(this.approximationFactor), new EncryptionKey(newKey));
    this.textEncryptionKey = new EncryptionKey(newKey);
    this.deterministicEncryptionKey = new EncryptionKey(newKey);
  }

  /**
   * Encrypts a vector embedding.
   * @param {Array<number>} plaintextVector - The plaintext vector to encrypt.
   * @returns {[Array<number>, Buffer]} - A tuple containing the encrypted vector and metadata.
   */
  encryptVector(plaintextVector) {
    if (!Array.isArray(plaintextVector) || !plaintextVector.every(x => typeof x === 'number')) {
      throw new InvalidInputError("Plaintext vector must be an array of numbers");
    }

    // Shuffle the plaintext vector
    const shuffledVector = shuffle(this.textEncryptionKey, plaintextVector);

    // Encrypt the shuffled vector
    const encryptResult = encryptVector(this.vectorEncryptionKey, this.approximationFactor, shuffledVector);

    // Generate metadata
    const keyIdHeader = new KeyIdHeader((typeof this.keyId === 'string' ? this.keyId.split('').reduce((a, c) => a + c.charCodeAt(0), 0) : 1) % 9999, "Standalone", "VectorMetadata");
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
    if (!Array.isArray(encryptedVector) || !encryptedVector.every(x => typeof x === 'number')) {
      throw new InvalidInputError("Encrypted vector must be an array of numbers");
    }
    if (!Buffer.isBuffer(pairedIclInfo)) {
      throw new InvalidInputError("Metadata must be a Buffer");
    }

    /// Decode metadata
    const {
      keyIdHeader,
      remainingBytes
    } = decodeVersionPrefixedValue(pairedIclInfo);
    const iv = remainingBytes.subarray(0, 12);
    const authHashBytes = remainingBytes.subarray(12);

    // Convert the Buffer to an AuthHash object
    const authHash = new AuthHash(authHashBytes);

    // Decrypt the vector
    const shuffledVector = decryptVector(this.vectorEncryptionKey, this.approximationFactor, {
      ciphertext: encryptedVector,
      iv,
      authHash
    });

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
    return {
      ciphertext,
      iv,
      tag
    };
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
    const derivedKey = hkdf(this.deterministicEncryptionKey.getBytes(), 32, salt, info);

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
    if (encryptedData.length < 28) {
      // 12 (nonce) + 16 (min tag size)
      throw new InvalidInputError("Encrypted data too short");
    }

    // 1. Split components: nonce + ciphertext + tag
    const nonce = encryptedData.subarray(0, 12);
    const ciphertext = encryptedData.subarray(12, encryptedData.length - 16);
    const tag = encryptedData.subarray(encryptedData.length - 16);

    // 2. Derive the same key used for encryption
    const salt = Buffer.from('DCPE-Deterministic');
    const info = Buffer.from('deterministic_encryption_key');
    const derivedKey = hkdf(this.deterministicEncryptionKey.getBytes(), 32, salt, info);

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

// After the RagEncryptionClient class and its export:

/**
 * Encryption client instance for utility functions
 * @type {RagEncryptionClient}
 * @private
 */
let _clientInstance = null;

/**
 * Get or initialize the client instance
 * @param {Buffer} keys - Encryption keys
 * @returns {RagEncryptionClient}
 * @private
 */
function _getClientInstance(keys) {
  if (!_clientInstance) {
    _clientInstance = new RagEncryptionClient(keys);
  }
  return _clientInstance;
}

/**
 * Encrypts a text string using AES-GCM
 * @param {string} text - Text to encrypt
 * @param {Buffer} keys - Encryption keys
 * @param {Object} options - Encryption options
 * @returns {Object} - Encrypted text, IV, and authentication tag
 */
function encryptText(text, keys) {
  const client = _getClientInstance(keys);
  return client.encryptText(text);
}

/**
 * Decrypts an AES-GCM encrypted text
 * @param {Object} encryptedText - Encrypted text object with ciphertext, iv, and tag
 * @param {Buffer} keys - Encryption keys
 * @param {Object} options - Decryption options
 * @returns {string} - Decrypted text
 */
function decryptText(encryptedText, keys) {
  const client = _getClientInstance(keys);
  return client.decryptText(encryptedText.ciphertext, encryptedText.iv, encryptedText.tag);
}

/**
 * Encrypts text deterministically using AES-GCM
 * @param {string} value - Value to encrypt
 * @param {Buffer} keys - Encryption keys
 * @param {Object} options - Encryption options
 * @returns {Buffer} - Encrypted value
 */
function encryptDeterministicText(value, keys) {
  const client = _getClientInstance(keys);
  return client.encryptDeterministicText(value);
}

/**
 * Decrypts deterministically encrypted text
 * @param {Buffer} encryptedValue - Encrypted value
 * @param {Buffer} keys - Encryption keys
 * @param {Object} options - Decryption options
 * @returns {string} - Decrypted value
 */
function decryptDeterministicText(encryptedValue, keys) {
  const client = _getClientInstance(keys);
  return client.decryptDeterministicText(encryptedValue);
}

var index = /*#__PURE__*/Object.freeze({
    __proto__: null,
    RagEncryptionClient: RagEncryptionClient,
    decryptDeterministicText: decryptDeterministicText,
    decryptMetadataField: decryptDeterministicText,
    decryptText: decryptText,
    encryptDeterministicText: encryptDeterministicText,
    encryptMetadataField: encryptDeterministicText,
    encryptText: encryptText
});

/**
 * Validate configuration object against schema
 * @param {Object} config - Configuration to validate
 * @param {Object} schema - Schema definition
 * @returns {Object} - Validated configuration with defaults
 */
function validateConfig(config, schema) {
  const result = {
    ...config
  };
  const errors = [];

  // Check required fields
  if (schema.required) {
    for (const field of schema.required) {
      if (result[field] === undefined) {
        errors.push(`Missing required field: ${field}`);
      }
    }
  }

  // Apply defaults
  if (schema.properties) {
    for (const [key, prop] of Object.entries(schema.properties)) {
      if (result[key] === undefined && prop.default !== undefined) {
        result[key] = prop.default;
      }

      // Type validation
      if (result[key] !== undefined && prop.type) {
        const type = typeof result[key];
        if (type !== prop.type) {
          errors.push(`Type mismatch for ${key}: expected ${prop.type}, got ${type}`);
        }
      }
    }
  }
  if (errors.length > 0) {
    throw new Error(`Configuration validation failed: ${errors.join(', ')}`);
  }
  return result;
}

/**
 * Create a schema for configuration validation
 * @param {Object} properties - Schema properties
 * @param {Array<string>} required - Required field names
 * @returns {Object} - Schema definition
 */
function createSchema(properties) {
  let required = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : [];
  return {
    properties,
    required
  };
}

var configValidator = /*#__PURE__*/Object.freeze({
    __proto__: null,
    createSchema: createSchema,
    validateConfig: validateConfig
});

/**
 * Base adapter interface for vector databases
 * This is an abstract class that should be extended to create specific database adapters
 */
class BaseAdapter {
  /**
   * Create a new adapter instance
   * @param {Object} config - Configuration options
   */
  constructor() {
    let config = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
    this.config = config;
  }

  /**
   * Connect to the vector database
   * @returns {Promise<void>}
   */
  async connect() {
    throw new Error('Method not implemented: connect');
  }

  /**
   * Disconnect from the vector database
   * @returns {Promise<void>}
   */
  async disconnect() {
    throw new Error('Method not implemented: disconnect');
  }

  /**
   * Insert vectors into the database
   * @param {Array<Object>} vectors - Vectors to insert
   * @returns {Promise<Array>} - Inserted IDs
   */
  async insert(vectors) {
    throw new Error('Method not implemented: insert');
  }

  /**
   * Search for vectors in the database
   * @param {Array<number>} queryVector - Query vector
   * @param {Object} options - Search options
   * @returns {Promise<Array<Object>>} - Search results
   */
  async search(queryVector) {
    throw new Error('Method not implemented: search');
  }
}

/**
 * Main DCPE class providing a simple interface to the library's functionality
 */
class DCPE {
  /**
   * Create a new DCPE instance
   * @param {Object} config - Configuration options
   * @param {string} [config.keyProvider='local'] - Key provider type ('local', 'vault', etc.)
   * @param {Object} [config.keyProviderConfig={}] - Configuration for key provider
   * @param {Object} [config.vectorConfig={}] - Configuration for vector operations
   */
  constructor() {
    let config = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
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
   */
  _initializeKeyProvider() {
    const {
      keyProvider: providerType,
      keyProviderConfig
    } = this.config;
    switch (providerType.toLowerCase()) {
      case 'local':
        this.keyProvider = new LocalKeyProvider(keyProviderConfig);
        break;
      // Add other key providers as needed
      default:
        throw new Error(`Unsupported key provider: ${providerType}`);
    }
  }

  /**
   * Generate encryption keys
   * @param {Object} options - Options for key generation
   * @returns {Promise<Object>} - Generated keys
   */
  async generateKeys() {
    return await generateEncryptionKeys();
  }

  /**
   * Set encryption keys
   * @param {Object} encryptionKeys - Encryption keys to set
   */
  setKeys(encryptionKeys) {
    this.keyProvider.setKeys(encryptionKeys);
  }

  /**
   * Encrypt a vector using DCPE
   * @param {Array<number>} vector - Vector to encrypt
   * @param {Object} options - Encryption options
   * @returns {Array<number>} - Encrypted vector
   */
  encryptVector(vector) {
    let options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
    const keys = this.keyProvider.getKeys();
    return encryptVector(vector, keys, options);
  }

  /**
   * Decrypt a vector using DCPE
   * @param {Array<number>} encryptedVector - Encrypted vector
   * @param {Object} options - Decryption options
   * @returns {Array<number>} - Decrypted vector
   */
  decryptVector(encryptedVector) {
    let options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
    const keys = this.keyProvider.getKeys();
    return decryptVector(encryptedVector, keys, options);
  }

  /**
   * Encrypt text using AES-GCM
   * @param {string} text - Text to encrypt
   * @param {Object} options - Encryption options
   * @returns {string} - Encrypted text
   */
  encryptText(text) {
    const keys = this.keyProvider.getKeys();
    return encryptText(text, keys);
  }

  /**
   * Decrypt text using AES-GCM
   * @param {string} encryptedText - Encrypted text
   * @param {Object} options - Decryption options
   * @returns {string} - Decrypted text
   */
  decryptText(encryptedText) {
    const keys = this.keyProvider.getKeys();
    return decryptText(encryptedText, keys);
  }

  /**
   * Encrypt metadata field using deterministic encryption
   * @param {string|number} value - Value to encrypt
   * @param {Object} options - Encryption options
   * @returns {string} - Encrypted value
   */
  encryptMetadata(value) {
    const keys = this.keyProvider.getKeys();
    return encryptDeterministicText(value, keys);
  }

  /**
   * Decrypt metadata field
   * @param {string} encryptedValue - Encrypted value
   * @param {Object} options - Decryption options
   * @returns {string|number} - Decrypted value
   */
  decryptMetadata(encryptedValue) {
    const keys = this.keyProvider.getKeys();
    return decryptDeterministicText(encryptedValue, keys);
  }
}

/**
 * DCPE-JS - Distance Comparison Preserving Encryption for JavaScript
 * Main entry point for the library
 */


// Export version
const VERSION = '0.1.0';

export { BaseAdapter, DCPE, VERSION, configValidator as configUtils, index$3 as crypto, index$5 as exceptions, index$2 as headers, index$1 as keyProvider, index$4 as keys, index as ragEncryption };
//# sourceMappingURL=index.esm.js.map
