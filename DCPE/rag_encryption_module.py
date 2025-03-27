# rag_encryption_module.py

import numpy as np
import secrets
import os
import json
import base64
import hmac
from typing import List, Tuple

from DCPE.crypto_module import encrypt_vector, decrypt_vector, AuthHash, EncryptResult, shuffle, unshuffle
from DCPE.keys_module import VectorEncryptionKey, EncryptionKey, ScalingFactor, generate_random_key
from DCPE.headers_module import KeyIdHeader, EdekType, PayloadType, encode_vector_metadata, decode_version_prefixed_value
from DCPE.exceptions_module import DecryptError

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import hmac as crypto_hmac


class RagEncryptionClient:
    """
    Client for orchestrating RAG encryption and decryption operations.
    """
    def __init__(self, encryption_key: bytes, approximation_factor: float):
        """
        Initializes the RagEncryptionClient with a raw encryption key and approximation factor.

        Args:
            encryption_key (bytes): Raw bytes of the encryption key.
            approximation_factor (float): Approximation factor for vector encryption.
        """
        if not isinstance(encryption_key, bytes):
            raise TypeError("encryption_key must be bytes")
        if not isinstance(approximation_factor, float):
            raise TypeError("approximation_factor must be a float")
        if len(encryption_key) < 32:
            raise ValueError("Encryption key must be at least 32 bytes long")

        # For simplicity in this basic version, directly using raw key bytes and scaling factor.
        # In a more complete version, use VectorEncryptionKey and derive key from secret etc.
        self.vector_encryption_key = VectorEncryptionKey(
            scaling_factor=ScalingFactor(approximation_factor),
            key=EncryptionKey(encryption_key)
        )
        self.approximation_factor = approximation_factor

        self.text_encryption_key = EncryptionKey(encryption_key) # Using the same raw key for text encryption for simplicity in this basic version
        self.deterministic_encryption_key = EncryptionKey(encryption_key) # Using the same raw key for deterministic encryption for simplicity in this basic version
    
    # Function to get or create encryption key (Modified to handle JSON file)
    def get_or_create_encryption_key(KEY_FILE: str) -> bytes:
        try:
            if os.path.exists(KEY_FILE):
                # Load existing key
                with open(KEY_FILE, 'r') as f:
                    key_data = json.load(f)
                    return base64.b64decode(key_data["key"])
            else:
                # Generate new key
                new_key = generate_random_key().get_bytes()
                # Save it for future use
                with open(KEY_FILE, 'w') as f:
                    json.dump({"key": base64.b64encode(new_key).decode('utf-8')}, f)
                return new_key
        except Exception as e:
            print(f"Error handling encryption key: {e}")
            # Fallback to generating a new key (note: this will make previous data unreadable)
            return generate_random_key().get_bytes()

    def encrypt_vector(self, plaintext_vector: List[float]) -> Tuple[List[float], bytes]:
        """
        Encrypts a plaintext vector embedding with additional shuffling for enhanced security.

        Args:
            plaintext_vector (List[float]): The plaintext vector embedding as a list of floats.

        Returns:
            Tuple[List[float], bytes]: A tuple containing the encrypted vector and the paired ICL info (encoded metadata).
        """
        if not isinstance(plaintext_vector, list):
            raise TypeError("plaintext_vector must be a list")
        if not all(isinstance(x, float) for x in plaintext_vector):
            raise TypeError("plaintext_vector must be a list of floats")

        # Step 1: Shuffle the plaintext vector
        shuffled_vector = shuffle(self.text_encryption_key, plaintext_vector)

        # Step 2: Encrypt the shuffled vector
        encrypt_result = encrypt_vector(
            key=self.vector_encryption_key,
            approximation_factor=self.approximation_factor,
            message=shuffled_vector
        )

        # Steps 3-4: Generate metadata as before
        key_id_header = KeyIdHeader.create_header(
            edek_type=EdekType.STANDALONE,
            payload_type=PayloadType.VECTOR_METADATA,
            key_id=1
        )

        paired_icl_info = encode_vector_metadata(
            key_id_header=key_id_header,
            iv=encrypt_result.iv,
            auth_hash=encrypt_result.auth_hash
        )

        return encrypt_result.ciphertext, paired_icl_info


    def decrypt_vector(self, encrypted_vector: List[float], paired_icl_info: bytes) -> List[float]:
        """
        Decrypts an encrypted vector embedding and unshuffles it to restore original order.

        Args:
            encrypted_vector (List[float]): The encrypted vector embedding as a list of floats.
            paired_icl_info (bytes): The paired ICL info (encoded metadata) from encryption.

        Returns:
            List[float]: The decrypted plaintext vector embedding as a list of floats.
        """
        if not isinstance(encrypted_vector, list):
            raise TypeError("encrypted_vector must be a list")
        if not isinstance(paired_icl_info, bytes):
            raise TypeError("paired_icl_info must be bytes")
        if not all(isinstance(x, float) for x in encrypted_vector):
            raise TypeError("encrypted_vector must be a list of floats")

        # Step 1: Process metadata as before
        key_id_header, metadata_bytes_decoded = decode_version_prefixed_value(paired_icl_info)
        iv_bytes = metadata_bytes_decoded[:12]
        auth_hash_bytes = metadata_bytes_decoded[12:]
        auth_hash = AuthHash(auth_hash_bytes)

        encrypted_result = EncryptResult(
            ciphertext=encrypted_vector,
            iv=iv_bytes,
            auth_hash=auth_hash
        )

        # Step 2: Decrypt the vector (still shuffled)
        shuffled_plaintext_vector = decrypt_vector(
            key=self.vector_encryption_key,
            approximation_factor=self.approximation_factor,
            encrypted_result=encrypted_result
        )
        
        # Step 3: Unshuffle to restore original order
        original_plaintext_vector = unshuffle(self.text_encryption_key, shuffled_plaintext_vector)
        
        return original_plaintext_vector


    def encrypt_text(self, plaintext: str) -> Tuple[bytes, bytes, bytes]: # Return tuple with ciphertext, iv, and tag
        """Encrypts plaintext using AES-GCM and returns ciphertext, IV, and authentication tag."""
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be a string")
        
        iv = secrets.token_bytes(12)  # Generate a unique IV
        cipher = Cipher(algorithms.AES(self.text_encryption_key.get_bytes()), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize() # AES-GCM encrypt and finalize
        tag = encryptor.tag # Get the authentication tag

        return ciphertext, iv, tag # Return ciphertext, IV, and tag


    def decrypt_text(self, encrypted_text: bytes, iv: bytes, tag: bytes) -> str: # Expect tag as argument
        """Decrypts AES-GCM encrypted text, now expecting IV and authentication tag."""
        if not isinstance(encrypted_text, bytes):
            raise TypeError("encrypted_text must be bytes")
        if not isinstance(iv, bytes):
            raise TypeError("iv must be bytes")
        if len(iv) != 12:
            raise ValueError("IV must be 12 bytes long for AES-GCM")
        if not isinstance(tag, bytes): # Validate tag argument
            raise TypeError("Authentication tag must be bytes")

        cipher = Cipher(algorithms.AES(self.text_encryption_key.get_bytes()), modes.GCM(iv, tag), backend=default_backend()) # Pass tag to GCM mode
        decryptor = cipher.decryptor()
        try:
            plaintext_bytes = decryptor.update(encrypted_text) + decryptor.finalize() # AES-GCM decrypt and finalize
            return plaintext_bytes.decode('utf-8') # Decode bytes to string
        except Exception as e: # cryptography library can raise various exceptions on decryption failure
            raise DecryptError(f"Text decryption failed: {e}")


    def encrypt_deterministic_text(self, plaintext: str) -> bytes:
        """Deterministically encrypts plaintext using SIV mode for authenticated deterministic encryption."""
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be a string")
        
        # 1. Derive a deterministic key for this operation
        # Use HKDF to derive a specific key for deterministic encryption        
        derived_key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=b'DCPE-Deterministic',  # Domain separation constant
            info=b'deterministic_encryption_key'
        ).derive(self.deterministic_encryption_key.get_bytes())
        
        # 2. Create deterministic "nonce" from plaintext using the derived key to enhance security        
        h = crypto_hmac.HMAC(key=derived_key, algorithm=hashes.SHA256())
        h.update(plaintext.encode('utf-8'))
        deterministic_nonce = h.finalize()[:12]  # Use first 12 bytes for GCM nonce
        
        # 3. Encrypt with AES-GCM-SIV mode which provides determinism and authentication
        aesgcmsiv = AESGCMSIV(derived_key)
        ciphertext = aesgcmsiv.encrypt(
            nonce=deterministic_nonce,
            data=plaintext.encode('utf-8'),
            associated_data=None  # No AAD in this case
        )
        
        # 4. Prepend nonce to ciphertext for decryption
        return deterministic_nonce + ciphertext

    def decrypt_deterministic_text(self, encrypted_data: bytes) -> str:
        """Decrypts deterministically encrypted text using SIV mode."""
        if not isinstance(encrypted_data, bytes):
            raise TypeError("encrypted_data must be bytes")
        if len(encrypted_data) < 12:
            raise ValueError("Encrypted data too short")
        
        # 1. Extract nonce and ciphertext
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        # 2. Derive the same key used for encryption
        derived_key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=b'DCPE-Deterministic',
            info=b'deterministic_encryption_key'
        ).derive(self.deterministic_encryption_key.get_bytes())
        
        # 3. Decrypt with AES-GCM-SIV
        aesgcmsiv = AESGCMSIV(derived_key)
        try:
            plaintext = aesgcmsiv.decrypt(
                nonce=nonce,
                data=ciphertext,
                associated_data=None
            )
            return plaintext.decode('utf-8')
        except Exception as e:
            raise DecryptError(f"Deterministic text decryption failed: {e}")

   


class PlaintextVector:
    """Represents a plaintext vector embedding with associated metadata paths."""
    def __init__(self, plaintext_vector: List[float]):
        self.plaintext_vector = plaintext_vector


class EncryptedVector:
    """Represents an encrypted vector embedding with associated metadata and paths."""
    def __init__(self, encrypted_vector: List[float], paired_icl_info: bytes):
        self.encrypted_vector = encrypted_vector
        self.paired_icl_info = paired_icl_info