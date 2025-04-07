import { RagEncryptionClient } from "../rag_encryption/index.js";
import { AuthHash } from "../crypto/index.js";

describe("RagEncryptionClient Integration Tests", () => {
    const encryptionKey = Buffer.from("testkey12345678901234567890123456");

    test("Vector encryption and decryption should be consistent", () => {
        const client = new RagEncryptionClient(encryptionKey, 1.0);
        const plaintextVector = [1.0, 2.0, 3.0];

        // Updated to use array destructuring for tuple return format
        const [encryptedVector, metadata] = client.encryptVector(plaintextVector);
        const decryptedVector = client.decryptVector(encryptedVector, metadata);

        // Check that each element is "close enough" instead of exactly equal
        expect(decryptedVector.length).toBe(plaintextVector.length);
        for (let i = 0; i < plaintextVector.length; i++) {
            expect(decryptedVector[i]).toBeCloseTo(plaintextVector[i], 5); // Increased precision
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
    
    // New test for async key rotation
    test("Key rotation should work correctly", async () => {
        const client = new RagEncryptionClient(encryptionKey);
        const plaintext = "Test before rotation";
        
        // Encrypt with original key
        const encryptedData = client.encryptDeterministicText(plaintext);
        
        // Rotate to a new key
        const newKey = Buffer.from("newkey1234567890123456789012345678");
        await client.rotateKey(newKey);
        
        // Try to decrypt with new key (should fail)
        expect(() => client.decryptDeterministicText(encryptedData)).toThrow();
        
        // Encrypt with new key
        const newEncryptedData = client.encryptDeterministicText(plaintext);
        const decryptedText = client.decryptDeterministicText(newEncryptedData);
        
        // Verify still works with new key
        expect(decryptedText).toBe(plaintext);
        
        // Verify the encrypted data is different with the new key
        expect(encryptedData).not.toEqual(newEncryptedData);
    });
        // Test key provider functionality
        test("Client should initialize with key provider", async () => {
            const mockKeyProvider = {
                getKey: jest.fn().mockResolvedValue(encryptionKey)
            };
            
            // Use create() instead of constructor
            const client = await RagEncryptionClient.create(null, 1.0, mockKeyProvider, "test-key-id");
            expect(client.keyId).toBe("test-key-id");
            expect(mockKeyProvider.getKey).toHaveBeenCalledWith("test-key-id");
        });
    
    // Test key rotation with provider
    test("Key rotation should work with key provider", async () => {
        const mockKeyProvider = {
            getKey: jest.fn()
                .mockResolvedValueOnce(encryptionKey)
                .mockResolvedValueOnce(Buffer.from("newkey1234567890123456789012345678"))
        };
        
        // Use create() instead of constructor
        const client = await RagEncryptionClient.create(null, 1.0, mockKeyProvider, "old-key-id");
        await client.rotateKey(null, "new-key-id");
        
        expect(client.keyId).toBe("new-key-id");
        expect(mockKeyProvider.getKey).toHaveBeenCalledWith("new-key-id");
    });
});