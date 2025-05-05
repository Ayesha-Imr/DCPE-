from phe import paillier
import os
import numpy as np
import hashlib
from Crypto.Cipher import AES
import base64
import pickle

# Generate keys (only once, must be securely stored)
public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)

# Generate AES Key (must be securely stored, 16/24/32 bytes for AES-128/192/256)
def get_or_create_key():
    key_file = "secure_key_2.bin"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        # Generate new key
        key = os.urandom(32)
        # Save key (in production, encrypt this file)
        with open(key_file, "wb") as f:
            f.write(key)
        return key

# Use the persistent key
AES_KEY = get_or_create_key()



def secure_encrypt_vector(vector, key=AES_KEY):
    """Encrypt vector using random projection to preserve similarity."""
    # Generate a random projection matrix using the key
    np.random.seed(int.from_bytes(hashlib.sha256(key).digest()[:4], 'big') % (2**32))
    projection_matrix = np.random.randn(len(vector), len(vector))
    
    # Normalize the projection matrix to preserve distances
    projection_matrix /= np.linalg.norm(projection_matrix, axis=0)
    
    # Apply random projection
    transformed = projection_matrix @ vector
    
    return transformed.astype('float32')

def secure_decrypt_vector(encrypted_vector, key=AES_KEY):
    """Decrypt a vector encrypted with secure_encrypt_vector."""
    # Regenerate the same projection matrix
    np.random.seed(int.from_bytes(hashlib.sha256(key).digest()[:4], 'big') % (2**32))
    projection_matrix = np.random.randn(len(encrypted_vector), len(encrypted_vector))
    projection_matrix /= np.linalg.norm(projection_matrix, axis=0)
    
    # Apply inverse transformation
    projection_matrix_inv = np.linalg.pinv(projection_matrix)  # Use pseudo-inverse for stability
    original = projection_matrix_inv @ encrypted_vector
    
    return original.astype('float32')


def encrypt_document_aes(document_content, key=AES_KEY):
    """Encrypt document content using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(document_content.encode('utf-8'))
    encrypted = nonce + tag + ciphertext
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_document_aes(encrypted_document, key=AES_KEY):
    """Decrypt document content using AES-GCM."""
    encrypted = base64.b64decode(encrypted_document)
    nonce, tag, ciphertext = encrypted[:16], encrypted[16:32], encrypted[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    document_content = cipher.decrypt_and_verify(ciphertext, tag)
    return document_content.decode('utf-8')

def encrypt_doc_id(doc_id):
    """Encrypt document ID with Paillier."""
    # Convert doc_id to integer if it's not already
    doc_id_int = int(doc_id) if not isinstance(doc_id, int) else doc_id
    
    # Encrypt with Paillier public key
    encrypted_number = public_key.encrypt(doc_id_int)
    
    # Serialize the encrypted number
    serialized = pickle.dumps(encrypted_number)
    
    # Return base64 encoded for storage
    return base64.b64encode(serialized).decode('utf-8')

def decrypt_doc_id(encrypted_id):
    """Decrypt document ID using Paillier."""
    # Decode from base64
    serialized = base64.b64decode(encrypted_id)
    
    # Deserialize to get the encrypted number
    encrypted_number = pickle.loads(serialized)
    
    # Decrypt using private key
    doc_id = private_key.decrypt(encrypted_number)
    
    return doc_id
