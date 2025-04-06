import { 
    KeyIdHeader, 
    EdekType, 
    PayloadType, 
    VectorMetadata,
    encodeVectorMetadata,
    decodeVersionPrefixedValue
} from "../headers/index.js";
import { AuthHash } from "../crypto/index.js";
import { InvalidInputError } from "../exceptions/index.js";

describe("Headers Module", () => {
    // Original test
    test("KeyIdHeader should serialize and deserialize correctly", () => {
        const header = new KeyIdHeader(1, EdekType.STANDALONE, PayloadType.VECTOR_METADATA);
        const serialized = header.writeToBytes();
        const deserialized = KeyIdHeader.parseFromBytes(serialized);

        expect(deserialized.keyId).toBe(1);
        expect(deserialized.edekType).toBe(EdekType.STANDALONE);
        expect(deserialized.payloadType).toBe(PayloadType.VECTOR_METADATA);
    });

    // Test static createHeader factory method
    test("KeyIdHeader.createHeader should create a valid header", () => {
        const header = KeyIdHeader.createHeader(
            EdekType.STANDALONE,
            PayloadType.VECTOR_METADATA,
            42
        );

        expect(header.keyId).toBe(42);
        expect(header.edekType).toBe(EdekType.STANDALONE);
        expect(header.payloadType).toBe(PayloadType.VECTOR_METADATA);
    });

    // Test input validation for KeyIdHeader
    test("KeyIdHeader should validate inputs", () => {
        expect(() => new KeyIdHeader("not-a-number", EdekType.STANDALONE, PayloadType.VECTOR_METADATA))
            .toThrow(TypeError);
        expect(() => new KeyIdHeader(1, "not-an-edek-type", PayloadType.VECTOR_METADATA))
            .toThrow(TypeError);
        expect(() => new KeyIdHeader(1, EdekType.STANDALONE, "not-a-payload-type"))
            .toThrow(TypeError);
    });

    // Test KeyIdHeader with different values
    test("KeyIdHeader should work with different valid values", () => {
        const testCases = [
            {
                keyId: 0,
                edekType: EdekType.STANDALONE,
                payloadType: PayloadType.DETERMINISTIC_FIELD
            },
            {
                keyId: 9999,
                edekType: EdekType.SAAS_SHIELD,
                payloadType: PayloadType.STANDARD_EDEK
            },
            {
                keyId: 4294967295, // max uint32
                edekType: EdekType.DATA_CONTROL_PLATFORM,
                payloadType: PayloadType.VECTOR_METADATA
            }
        ];

        for (const testCase of testCases) {
            const header = new KeyIdHeader(testCase.keyId, testCase.edekType, testCase.payloadType);
            const serialized = header.writeToBytes();
            const deserialized = KeyIdHeader.parseFromBytes(serialized);
            
            expect(deserialized.keyId).toBe(testCase.keyId);
            expect(deserialized.edekType).toBe(testCase.edekType);
            expect(deserialized.payloadType).toBe(testCase.payloadType);
        }
    });

    // Test parseFromBytes error cases
    test("KeyIdHeader.parseFromBytes should validate input bytes", () => {
        expect(() => KeyIdHeader.parseFromBytes(Buffer.alloc(5))) // Too short
            .toThrow(InvalidInputError);
            
        const badPaddingBytes = Buffer.alloc(6);
        badPaddingBytes[5] = 1; // Non-zero padding byte
        expect(() => KeyIdHeader.parseFromBytes(badPaddingBytes))
            .toThrow(InvalidInputError);
    });

    // Test VectorMetadata constructor
    test("VectorMetadata should initialize correctly", () => {
        const keyIdHeader = new KeyIdHeader(1, EdekType.STANDALONE, PayloadType.VECTOR_METADATA);
        const iv = Buffer.alloc(12);
        const authHash = new AuthHash(Buffer.alloc(32));
        
        const metadata = new VectorMetadata(keyIdHeader, iv, authHash);
        
        expect(metadata.keyIdHeader).toBe(keyIdHeader);
        expect(metadata.iv).toBe(iv);
        expect(metadata.authHash).toBe(authHash);
    });

    // Test VectorMetadata input validation
    test("VectorMetadata should validate inputs", () => {
        const keyIdHeader = new KeyIdHeader(1, EdekType.STANDALONE, PayloadType.VECTOR_METADATA);
        const iv = Buffer.alloc(12);
        const authHash = new AuthHash(Buffer.alloc(32));
        
        expect(() => new VectorMetadata("not-a-header", iv, authHash))
            .toThrow(TypeError);
        expect(() => new VectorMetadata(keyIdHeader, "not-a-buffer", authHash))
            .toThrow(TypeError);
        expect(() => new VectorMetadata(keyIdHeader, iv, "not-an-auth-hash"))
            .toThrow(TypeError);
    });

    // Test encodeVectorMetadata
    test("encodeVectorMetadata should encode correctly", () => {
        const keyIdHeader = new KeyIdHeader(1, EdekType.STANDALONE, PayloadType.VECTOR_METADATA);
        const iv = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        const authHash = new AuthHash(Buffer.alloc(32, 0xFF)); // filled with 0xFF
        
        const encoded = encodeVectorMetadata(keyIdHeader, iv, authHash);
        
        // Check that the bytes are in correct order
        const headerBytes = keyIdHeader.writeToBytes();
        expect(encoded.subarray(0, 6)).toEqual(headerBytes);
        expect(encoded.subarray(6, 18)).toEqual(iv);
        expect(encoded.subarray(18, 50)).toEqual(authHash.getBytes());
    });

    // Test decodeVersionPrefixedValue
    test("decodeVersionPrefixedValue should decode correctly", () => {
        const keyIdHeader = new KeyIdHeader(1, EdekType.STANDALONE, PayloadType.VECTOR_METADATA);
        const headerBytes = keyIdHeader.writeToBytes();
        const remainingData = Buffer.from([1, 2, 3, 4, 5]);
        const combined = Buffer.concat([headerBytes, remainingData]);
        
        const { keyIdHeader: decoded, remainingBytes } = decodeVersionPrefixedValue(combined);
        
        expect(decoded.keyId).toBe(keyIdHeader.keyId);
        expect(decoded.edekType).toBe(keyIdHeader.edekType);
        expect(decoded.payloadType).toBe(keyIdHeader.payloadType);
        expect(remainingBytes).toEqual(remainingData);
    });

    // Test decodeVersionPrefixedValue error case
    test("decodeVersionPrefixedValue should validate input bytes", () => {
        expect(() => decodeVersionPrefixedValue(Buffer.alloc(5))) // Too short
            .toThrow(InvalidInputError);
    });

    // Test full round trip: encodeVectorMetadata -> decodeVersionPrefixedValue
    test("Vector metadata round trip encoding and decoding", () => {
        const keyIdHeader = new KeyIdHeader(1, EdekType.STANDALONE, PayloadType.VECTOR_METADATA);
        const iv = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        const authHash = new AuthHash(Buffer.alloc(32, 0xFF));
        
        const encoded = encodeVectorMetadata(keyIdHeader, iv, authHash);
        const { keyIdHeader: decoded, remainingBytes } = decodeVersionPrefixedValue(encoded);
        
        expect(decoded.keyId).toBe(keyIdHeader.keyId);
        expect(decoded.edekType).toBe(keyIdHeader.edekType);
        expect(decoded.payloadType).toBe(keyIdHeader.payloadType);
        
        const decodedIv = remainingBytes.subarray(0, 12);
        const decodedAuthHashBytes = remainingBytes.subarray(12);
        
        expect(decodedIv).toEqual(iv);
        expect(decodedAuthHashBytes).toEqual(authHash.getBytes());
    });
});