import crypto from 'crypto';
import { InvalidKeyError } from '../exceptions/index.js';

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
        return (
            other instanceof VectorEncryptionKey &&
            this.scalingFactor.equals(other.scalingFactor) &&
            this.key.equals(other.key)
        );
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

export {
    EncryptionKey,
    ScalingFactor,
    VectorEncryptionKey,
    generateRandomKey
};