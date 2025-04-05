import { RagEncryptionClient } from "../rag_encryption/index.js";

describe("RagEncryptionClient Integration Tests", () => {
    const encryptionKey = Buffer.from("testkey12345678901234567890123456");

    test("Vector encryption and decryption should be consistent", () => {
        const client = new RagEncryptionClient(encryptionKey, 1.0);
        const plaintextVector = [1.0, 2.0, 3.0];

        const { encryptedVector, metadata } = client.encryptVector(plaintextVector);
        const decryptedVector = client.decryptVector(encryptedVector, metadata);

        // Check that each element is "close enough" instead of exactly equal
        expect(decryptedVector.length).toBe(plaintextVector.length);
        for (let i = 0; i < plaintextVector.length; i++) {
            expect(decryptedVector[i]).toBeCloseTo(plaintextVector[i], 1); // 1 decimal place precision
        }
    });

    test("Text encryption and decryption should be consistent", () => {
        const client = new RagEncryptionClient(encryptionKey);
        const plaintext = "Hello, World!";

        const { ciphertext, iv, tag } = client.encryptText(plaintext);
        const decryptedText = client.decryptText(ciphertext, iv, tag);

        expect(decryptedText).toBe(plaintext);
    });

    test("Deterministic text encryption and decryption should be consistent", () => {
        const client = new RagEncryptionClient(encryptionKey);
        const plaintext = "Deterministic Test";

        const encryptedData = client.encryptDeterministicText(plaintext);
        const decryptedText = client.decryptDeterministicText(encryptedData);

        expect(decryptedText).toBe(plaintext);
    });

    test("Deterministic encryption should produce the same ciphertext for the same input", () => {
        const client = new RagEncryptionClient(encryptionKey);
        const plaintext = "Deterministic Test";

        const encryptedData1 = client.encryptDeterministicText(plaintext);
        const encryptedData2 = client.encryptDeterministicText(plaintext);

        expect(encryptedData1).toEqual(encryptedData2);
    });

    test("Deterministic encryption should produce different ciphertexts for different inputs", () => {
        const client = new RagEncryptionClient(encryptionKey);
        const plaintext1 = "Deterministic Test 1";
        const plaintext2 = "Deterministic Test 2";

        const encryptedData1 = client.encryptDeterministicText(plaintext1);
        const encryptedData2 = client.encryptDeterministicText(plaintext2);

        expect(encryptedData1).not.toEqual(encryptedData2);
    });
});