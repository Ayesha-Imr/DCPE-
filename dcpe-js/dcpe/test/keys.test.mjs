console.log("Test file loaded successfully");
import { EncryptionKey, ScalingFactor, VectorEncryptionKey } from "../keys/index.js";

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
});