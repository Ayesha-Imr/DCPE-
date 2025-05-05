# keys_module.py

import hashlib
import secrets

from DCPE.exceptions_module import InvalidKeyError

class EncryptionKey:
    """Represents a raw encryption key as bytes."""
    def __init__(self, key_bytes: bytes):
        if not isinstance(key_bytes, bytes):
            raise TypeError("EncryptionKey must be initialized with bytes")
        self.key_bytes = key_bytes

    def get_bytes(self):
        return self.key_bytes

    def __eq__(self, other):
        if isinstance(other, EncryptionKey):
            return self.key_bytes == other.key_bytes
        return False

    def __repr__(self):
        return f"EncryptionKey(bytes of length: {len(self.key_bytes)})"


class ScalingFactor:
    """Represents the scaling factor used in vector encryption."""
    def __init__(self, factor: float):
        if not isinstance(factor, float):
            raise TypeError("ScalingFactor must be initialized with a float")
        self.factor = factor

    def get_factor(self):
        return self.factor

    def __eq__(self, other):
        if isinstance(other, ScalingFactor):
            return self.factor == other.factor
        return False

    def __repr__(self):
        return f"ScalingFactor(factor: {self.factor})"


class VectorEncryptionKey:
    """Represents the combined key for vector encryption, including scaling factor and encryption key."""
    def __init__(self, scaling_factor: ScalingFactor, key: EncryptionKey):
        if not isinstance(scaling_factor, ScalingFactor):
            raise TypeError("VectorEncryptionKey scaling_factor must be a ScalingFactor instance")
        if not isinstance(key, EncryptionKey):
            raise TypeError("VectorEncryptionKey key must be an EncryptionKey instance")
        self.scaling_factor = scaling_factor
        self.key = key

    @classmethod
    def derive_from_secret(cls, secret: bytes, tenant_id: str, derivation_path: str):
        """Derives a VectorEncryptionKey from a master secret, tenant ID, and derivation path."""
        if not isinstance(secret, bytes):
            raise TypeError("Secret must be bytes")
        if not isinstance(tenant_id, str):
            raise TypeError("Tenant ID must be a string")
        if not isinstance(derivation_path, str):
            raise TypeError("Derivation Path must be a string")

        payload = f"{tenant_id}-{derivation_path}".encode('utf-8')
        hash_result_bytes = hashlib.hmac(secret, payload, hashlib.sha512).digest()
        return cls.unsafe_bytes_to_key(hash_result_bytes)

    @classmethod
    def unsafe_bytes_to_key(cls, key_bytes: bytes):
        """Constructs a VectorEncryptionKey from raw bytes. 
        Raises InvalidKeyError if key_bytes is not long enough.
        """
        if len(key_bytes) < 35:
            raise InvalidKeyError("Key bytes must be at least 35 bytes long")

        scaling_factor_bytes = key_bytes[:3]
        key_material_bytes = key_bytes[3:35]

        scaling_factor_u32 = int.from_bytes(b'\x00' + scaling_factor_bytes, byteorder='big')
        scaling_factor = ScalingFactor(float(scaling_factor_u32))
        encryption_key = EncryptionKey(key_material_bytes)

        return cls(scaling_factor=scaling_factor, key=encryption_key)

    def __eq__(self, other):
        if isinstance(other, VectorEncryptionKey):
            return self.scaling_factor == other.scaling_factor and self.key == other.key
        return False

    def __repr__(self):
        return f"VectorEncryptionKey(scaling_factor={self.scaling_factor}, key={self.key})"


def generate_random_key() -> EncryptionKey:
    """Generates a cryptographically random EncryptionKey (32 bytes)."""
    return EncryptionKey(secrets.token_bytes(32))