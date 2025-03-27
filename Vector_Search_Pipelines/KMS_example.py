# Example integration of client-side KMS and DCPE

import os
from DCPE.v2_rag_encryption_module import RagEncryptionClient
from DCPE.key_provider_module import KeyProvider, FileKeyProvider
from DCPE.keys_module import generate_random_key

# 1. Initialize key provider (this simulates client-side KMS)
key_provider = FileKeyProvider("client_keys.json")

# 2. Generate/store a key if needed (only do this once)
try:
    encryption_key = key_provider.get_key("my_app_key")
    print("Using existing key")
except KeyError:
    # First-time setup: generate and store a new key
    print("Generating new encryption key")
    new_key = generate_random_key().get_bytes()
    key_provider.store_key(new_key, "my_app_key")

# 3. Initialize the encryption client using key provider
rag_client = RagEncryptionClient(
    key_provider=key_provider,
    key_id="my_app_key",
    approximation_factor=1.5
)

# 4. Use client for RAG operations - STORING DATA
document = "This is a sample document to demonstrate encrypted RAG."
chunks = [document[i:i+100] for i in range(0, len(document), 100)]

stored_data = []
for chunk in chunks:
    # Encrypt text content (standard encryption)
    encrypted_text, iv, tag = rag_client.encrypt_text(chunk)
    
    # Get embedding (in real app, you'd use an embedding model)
    sample_embedding = [0.1, 0.2, 0.3, 0.4, 0.5]
    
    # Encrypt embedding (searchable encryption)
    encrypted_vector, vector_metadata = rag_client.encrypt_vector(sample_embedding)
    
    # Encrypt metadata field (deterministic encryption for filtering)
    encrypted_source = rag_client.encrypt_deterministic_text("sample_document.pdf")
    
    # Store all encrypted data
    stored_data.append({
        "text": {
            "content": encrypted_text,
            "iv": iv,
            "tag": tag
        },
        "vector": encrypted_vector,
        "vector_metadata": vector_metadata,
        "source": encrypted_source
    })
    
print(f"Stored {len(stored_data)} encrypted chunks")

# 5. Use client for RAG operations - RETRIEVING DATA
for i, item in enumerate(stored_data):
    # Decrypt text
    decrypted_text = rag_client.decrypt_text(
        item["text"]["content"],
        item["text"]["iv"],
        item["text"]["tag"]
    )
    
    # Decrypt vector if needed
    decrypted_vector = rag_client.decrypt_vector(
        item["vector"],
        item["vector_metadata"]
    )
    
    # Decrypt source
    decrypted_source = rag_client.decrypt_deterministic_text(item["source"])
    
    print(f"Item {i}: Source={decrypted_source}, Text={decrypted_text[:20]}..., Vector={decrypted_vector[:3]}...")