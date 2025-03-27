# crypto_module.py (Corrected compute_auth_hash for float to bytes conversion)

import numpy as np
import secrets
import hashlib
import struct 
from typing import List

from DCPE.exceptions_module import DecryptError, InvalidKeyError
from DCPE.keys_module import VectorEncryptionKey, ScalingFactor, EncryptionKey
from cryptography.hazmat.primitives import hmac, hashes
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SHUFFLE_KEY = "One Ring to rule them all, One Ring to find them, One Ring to bring them all, and in the darkness bind them"

class AuthHash:
    """Represents an authentication hash."""
    def __init__(self, hash_bytes: bytes):
        if not isinstance(hash_bytes, bytes):
            raise TypeError("AuthHash must be initialized with bytes")
        if len(hash_bytes) != 32:
            raise ValueError("AuthHash must be 32 bytes long")
        self.hash_bytes = hash_bytes

    def get_bytes(self):
        return self.hash_bytes

    def __eq__(self, other):
        if isinstance(other, AuthHash):
            return self.hash_bytes == other.hash_bytes
        return False

    def __repr__(self):
        return f"AuthHash(bytes of length: {len(self.hash_bytes)})"


def sample_normal_vector(coin_rng: secrets.SystemRandom, message_dimensionality: int) -> np.ndarray:
    """Samples a vector from a multivariate normal distribution."""
    return np.random.normal(0.0, 1.0, message_dimensionality).astype(np.float32)

def sample_uniform_point(coin_rng: secrets.SystemRandom) -> float:
    """Samples a uniform random point between 0 and 1."""
    return coin_rng.random()

def calculate_uniform_point_in_ball(scaling_factor: ScalingFactor, approximation_factor: float, uniform_point: float, message_dimensionality: int) -> float:
    """Calculates a uniform point within an n-dimensional ball."""
    d_dimensional_ball_radius = scaling_factor.get_factor() / 4.0 * approximation_factor
    return d_dimensional_ball_radius * uniform_point**(1.0 / float(message_dimensionality))

def calculate_normalized_vector(multivariate_normal_sample: np.ndarray, uniform_point_in_ball: float) -> np.ndarray:
    """Calculates the normalized sampled vector."""
    norm = np.linalg.norm(multivariate_normal_sample)
    return (multivariate_normal_sample * uniform_point_in_ball / norm).astype(np.float32)

def generate_normalized_vector(key: VectorEncryptionKey, iv: bytes, approximation_factor: float, message_dimensionality: int) -> np.ndarray:
    """Generates the normalized noise vector for encryption."""
    coin_rng = secrets.SystemRandom() # Using SystemRandom for simplicity in Python - consider ChaCha20 with cryptography lib for closer parity to Rust
    multivariate_normal_sample = sample_normal_vector(coin_rng, message_dimensionality)
    uniform_point = sample_uniform_point(coin_rng)
    uniform_point_in_ball = calculate_uniform_point_in_ball(
        key.scaling_factor, approximation_factor, uniform_point, message_dimensionality
    )
    return calculate_normalized_vector(multivariate_normal_sample, uniform_point_in_ball)


def encrypt_vector(key: VectorEncryptionKey, approximation_factor: float, message: List[float]) -> 'EncryptResult':
    """Encrypts a vector embedding."""
    if key.scaling_factor.get_factor() == 0.0:
        raise InvalidKeyError("Scaling factor cannot be zero")

    message_np = np.array(message, dtype=np.float32)
    message_dimensionality = len(message)
    iv = secrets.token_bytes(12)

    if message_dimensionality == 0:
        ciphertext = np.zeros_like(message_np)
    else:
        ball_normalized_vector = generate_normalized_vector(
            key, iv, approximation_factor, message_dimensionality
        )
        ciphertext = (key.scaling_factor.get_factor() * message_np + ball_normalized_vector).astype(np.float32)

    if not np.isfinite(ciphertext).all():
        raise OverflowError("Embedding or approximation factor too large.")

    auth_hash = compute_auth_hash(key, approximation_factor, iv, ciphertext)

    return EncryptResult(ciphertext=ciphertext.tolist(), iv=iv, auth_hash=auth_hash)


def decrypt_vector(key: VectorEncryptionKey, approximation_factor: float, encrypted_result: 'EncryptResult') -> List[float]:
    """Decrypts an encrypted vector embedding."""
    if key.scaling_factor.get_factor() == 0.0:
        raise InvalidKeyError("Scaling factor cannot be zero")

    if not check_auth_hash(
        key, approximation_factor, encrypted_result.iv, np.array(encrypted_result.ciphertext, dtype=np.float32), encrypted_result.auth_hash
    ):
        raise DecryptError("Invalid authentication hash")

    ciphertext_np = np.array(encrypted_result.ciphertext, dtype=np.float32)
    message_dimensionality = len(encrypted_result.ciphertext)

    if message_dimensionality == 0:
        return np.zeros_like(ciphertext_np).tolist()

    ball_normalized_vector = generate_normalized_vector(
        key, encrypted_result.iv, approximation_factor, message_dimensionality
    )

    message = (ciphertext_np - ball_normalized_vector) / key.scaling_factor.get_factor()
    return message.tolist()


def compute_auth_hash(key: VectorEncryptionKey, approximation_factor: float, iv: bytes, encrypted_embedding: np.ndarray) -> AuthHash:
    """Computes the authentication hash for a vector embedding."""
    hmac_key = key.key.get_bytes()
    h = hashlib.sha256()
    h.update(hmac_key)
    h.update(struct.pack(">f", key.scaling_factor.get_factor())) # Use struct.pack to convert float to bytes (big-endian, float)
    h.update(struct.pack(">f", approximation_factor)) # Use struct.pack to convert float to bytes (big-endian, float)
    h.update(iv)
    for embedding_val in encrypted_embedding:
        h.update(embedding_val.tobytes()) # float to bytes
    auth_hash_bytes = h.digest()
    return AuthHash(auth_hash_bytes)


def check_auth_hash(key: VectorEncryptionKey, approximation_factor: float, iv: bytes, encrypted_embedding: np.ndarray, auth_hash: AuthHash) -> bool:
    """Verifies the authentication hash."""
    computed_hash = compute_auth_hash(key, approximation_factor, iv, encrypted_embedding)
    return computed_hash == auth_hash


def shuffle(key: EncryptionKey, input_list: list) -> list:
    """Deterministically shuffles a list based on a key."""
    rng = create_rng_for_shuffle(key)
    return sorted(input_list, key=lambda x: rng.random())


def unshuffle(key: EncryptionKey, input_list: list) -> list:
    """Deterministically unshuffles a list based on a key."""
    rng = create_rng_for_shuffle(key)
    indexed_input = list(enumerate(input_list))
    shuffled_indexed_input = sorted(indexed_input, key=lambda indexed_item: rng.random())
    original_indices_and_values = sorted(shuffled_indexed_input, key=lambda indexed_item_with_rand: indexed_item_with_rand[0][0]) # Sort by original index
    unshuffled_values = [value for index_and_rand_value, value in original_indices_and_values]
    return unshuffled_values


def create_rng_for_shuffle(key: EncryptionKey):
    """Creates a cryptographically strong RNG for shuffling."""
    # Use HMAC-SHA256 with a fixed key and the key as the message to create a seed
    h = hmac.HMAC(key.get_bytes(), hashes.SHA256())
    h.update(SHUFFLE_KEY.encode('utf-8'))
    seed_bytes = h.finalize()
    
    # Use AES-CTR with fixed nonce for deterministic encryption
    nonce = b'\x00' * 16  # Fixed nonce for determinism
    cipher = Cipher(algorithms.AES(seed_bytes[:32]), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    
    class CryptographicRandom:
        """A cryptographically secure random generator with deterministic seeding."""
        def __init__(self, encryptor):
            self.encryptor = encryptor
            self.buffer = b''
            
        def random(self):
            """Return a random float in [0.0, 1.0)"""
            # Get 8 random bytes (64 bits of randomness)
            if len(self.buffer) < 8:
                self.buffer += self.encryptor.update(b'\x00' * 64)
            result_bytes = self.buffer[:8]
            self.buffer = self.buffer[8:]
            # Convert to float between 0 and 1
            value = int.from_bytes(result_bytes, byteorder='big')
            return value / (2**(64) - 1)
    
    return CryptographicRandom(encryptor)


class EncryptResult:
    """Represents the result of vector encryption."""
    def __init__(self, ciphertext: List[float], iv: bytes, auth_hash: AuthHash):
        self.ciphertext = ciphertext
        self.iv = iv
        self.auth_hash = auth_hash

    def __repr__(self):
        return f"EncryptResult(ciphertext={self.ciphertext[:3]}..., iv={self.iv.hex()}..., auth_hash={self.auth_hash})"