# example_usage.py

import numpy as np
from DCPE.rag_encryption_module import RagEncryptionClient, PlaintextVector
from DCPE.keys_module import generate_random_key
from DCPE.exceptions_module import DCPEError

def main():
    try:
        # 1. Key Generation
        raw_encryption_key = generate_random_key().get_bytes()
        approximation_factor = 1.0  # Example approximation factor

        # 2. Client Initialization
        rag_client = RagEncryptionClient(
            encryption_key=raw_encryption_key,
            approximation_factor=approximation_factor
        )

        # 3. Vector Encryption and Decryption Roundtrip
        print("\n--- Vector Encryption and Decryption ---")
        plaintext_vector_list = [1.0, 2.0, 3.0, 4.0, 5.0]
        plaintext_vector = PlaintextVector(plaintext_vector_list)

        encrypted_vector_list, paired_icl_info = rag_client.encrypt_vector(plaintext_vector.plaintext_vector)
        print(f"Plaintext Vector: {plaintext_vector.plaintext_vector}")
        print(f"Encrypted Vector (first 5 elements): {encrypted_vector_list[:5]}...")
        print(f"Paired ICL Info (first 20 bytes): {paired_icl_info[:20].hex()}...")

        decrypted_vector_list = rag_client.decrypt_vector(encrypted_vector_list, paired_icl_info)
        print(f"Decrypted Vector (first 5 elements): {decrypted_vector_list[:5]}...")

        # Basic roundtrip test - for vectors, we use almost_equal due to approximation
        np.testing.assert_array_almost_equal(np.array(plaintext_vector.plaintext_vector), np.array(decrypted_vector_list), decimal=0)
        print("Vector Encryption Roundtrip Test: PASSED\n")


        print("\n--- Standard Text Encryption and Decryption (AES-GCM) ---")
        plaintext_text = "This is a confidential document for RAG, encrypted with AES-GCM."
        ciphertext_text_bytes, iv_bytes, tag_bytes = rag_client.encrypt_text(plaintext_text) # Capture tag_bytes
        print(f"Plaintext Text: {plaintext_text}")
        print(f"Ciphertext (first 20 bytes): {ciphertext_text_bytes[:20].hex()}...")
        print(f"IV (Initialization Vector): {iv_bytes.hex()}")
        print(f"Authentication Tag: {tag_bytes.hex()}") # Print authentication tag

        decrypted_text = rag_client.decrypt_text(ciphertext_text_bytes, iv_bytes, tag_bytes) # Pass tag_bytes to decrypt_text
        print(f"Decrypted Text: {decrypted_text}")

        # Basic roundtrip test for standard text
        assert plaintext_text == decrypted_text
        print("Standard Text Encryption Roundtrip Test (AES-GCM): PASSED\n")


        # 5. Deterministic Text Encryption and Decryption Roundtrip (AES-ECB - INSECURE)
        print("\n--- Deterministic Text Encryption and Decryption (AES-ECB - INSECURE - DEMO ONLY) ---")
        plaintext_deterministic_text = "Metadata to be encrypted deterministically for filtering."
        deterministic_ciphertext_bytes, _ = rag_client.encrypt_deterministic_text(plaintext_deterministic_text) # IV is empty for deterministic
        print(f"Plaintext Deterministic Text: {plaintext_deterministic_text}")
        print(f"Deterministic Ciphertext (first 20 bytes): {deterministic_ciphertext_bytes[:20].hex()}...")

        decrypted_deterministic_text = rag_client.decrypt_deterministic_text(deterministic_ciphertext_bytes)
        print(f"Decrypted Deterministic Text: {decrypted_deterministic_text}")

        # Basic roundtrip test for deterministic text
        assert plaintext_deterministic_text == decrypted_deterministic_text
        print("Deterministic Text Encryption Roundtrip Test (AES-ECB): PASSED\n")


        print("\n--- ALL TESTS PASSED ---")


    except DCPEError as e:
        print(f"A DCPEError occurred: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()