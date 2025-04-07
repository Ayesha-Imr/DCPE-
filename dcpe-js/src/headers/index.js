import { InvalidInputError } from '../exceptions/index.js';
import { AuthHash } from '../crypto/index.js';

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

        const { edekType, payloadType } = this._decodeTypeByte(typeByte);
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

        return { edekType, payloadType };
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
    return Buffer.concat([
        keyIdHeader.writeToBytes(),
        iv,
        authHash.getBytes()
    ]);
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

    return { keyIdHeader, remainingBytes };
}

export {
    EdekType,
    PayloadType,
    KeyIdHeader,
    VectorMetadata,
    encodeVectorMetadata,
    decodeVersionPrefixedValue
};