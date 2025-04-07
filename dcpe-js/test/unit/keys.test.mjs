console.log("Test file loaded successfully");
import { EncryptionKey, ScalingFactor, VectorEncryptionKey, generateRandomKey } from "../keys/index.js";
import { InvalidKeyError } from "../exceptions/index.js";

describe("Keys Module", () => {
    test("EncryptionKey should store and retrieve key bytes", () => {
        const keyBytes = Buffer.from("testkey12345678901234567890123456");
        const key = new EncryptionKey(keyBytes);
        expect(key.getBytes()).toEqual(keyBytes);
    });

    test("ScalingFactor should store and retrieve factor", () => {
        const factor = new ScalingFactor(1.5);
        expect(factor.getFactor()).toBe(1.5);
    });

    test("VectorEncryptionKey should combine scaling factor and encryption key", () => {
        const keyBytes = Buffer.from("testkey12345678901234567890123456");
        const scalingFactor = new ScalingFactor(1.5);
        const encryptionKey = new EncryptionKey(keyBytes);
        const vectorKey = new VectorEncryptionKey(scalingFactor, encryptionKey);

        expect(vectorKey.scalingFactor).toEqual(scalingFactor);
        expect(vectorKey.key).toEqual(encryptionKey);
    });
    test("EncryptionKey should enforce Buffer input", () => {
        expect(() => new EncryptionKey("not a buffer")).toThrow(TypeError);
    });

    test("ScalingFactor should enforce number input", () => {
        expect(() => new ScalingFactor("not a number")).toThrow(TypeError);
    });

    test("VectorEncryptionKey should enforce correct parameter types", () => {
        const keyBytes = Buffer.from("testkey12345678901234567890123456");
        const encryptionKey = new EncryptionKey(keyBytes);
        expect(() => new VectorEncryptionKey("not a scaling factor", encryptionKey)).toThrow(TypeError);
        expect(() => new VectorEncryptionKey(new ScalingFactor(1.0), "not an encryption key")).toThrow(TypeError);
    });

    test("EncryptionKey equals method should compare key bytes", () => {
        const keyBytes1 = Buffer.from("testkey12345678901234567890123456");
        const keyBytes2 = Buffer.from("testkey12345678901234567890123456");
        const keyBytes3 = Buffer.from("differentkey1234567890123456789012");
        
        const key1 = new EncryptionKey(keyBytes1);
        const key2 = new EncryptionKey(keyBytes2);
        const key3 = new EncryptionKey(keyBytes3);
        
        expect(key1.equals(key2)).toBe(true);
        expect(key1.equals(key3)).toBe(false);
    });

    test("VectorEncryptionKey.deriveFromSecret should derive a key correctly", () => {
        const secret = Buffer.from("secretkey123456789012345678901234");
        const tenantId = "tenant-123";
        const path = "embedding/customer";
        
        const vectorKey = VectorEncryptionKey.deriveFromSecret(secret, tenantId, path);
        
        expect(vectorKey).toBeInstanceOf(VectorEncryptionKey);
        expect(vectorKey.key).toBeInstanceOf(EncryptionKey);
        expect(vectorKey.scalingFactor).toBeInstanceOf(ScalingFactor);
    });

    test("VectorEncryptionKey.unsafeBytesToKey should construct key from bytes", () => {
        // Create a test buffer with 35+ bytes
        const testBytes = Buffer.alloc(40);
        testBytes[0] = 0; // First 3 bytes for scaling factor
        testBytes[1] = 0;
        testBytes[2] = 5; // Setting scaling factor to 5
        
        const vectorKey = VectorEncryptionKey.unsafeBytesToKey(testBytes);
        
        expect(vectorKey).toBeInstanceOf(VectorEncryptionKey);
        expect(vectorKey.scalingFactor.getFactor()).toBe(5);
        expect(vectorKey.key.getBytes().length).toBe(32);
    });

    test("VectorEncryptionKey.unsafeBytesToKey should throw on short input", () => {
        const shortBytes = Buffer.alloc(30); // Less than 35 bytes required
        expect(() => VectorEncryptionKey.unsafeBytesToKey(shortBytes)).toThrow(InvalidKeyError);
    });

    test("generateRandomKey should create a valid EncryptionKey", () => {
        const key = generateRandomKey();
        expect(key).toBeInstanceOf(EncryptionKey);
        expect(key.getBytes().length).toBe(32);
    });
});