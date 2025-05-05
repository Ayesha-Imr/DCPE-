# exceptions_module.py

class DCPEError(Exception):
    """Base class for all exceptions."""
    def __init__(self, message="An error occurred in the SDK"):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"DCPEError: {self.message}"

class InvalidConfigurationError(DCPEError):
    """Error while loading or with invalid configuration."""
    def __init__(self, msg="Invalid configuration"):
        super().__init__(f"InvalidConfigurationError: {msg}")

class InvalidKeyError(DCPEError):
    """Error with key used for encryption or decryption."""
    def __init__(self, msg="Invalid key"):
        super().__init__(f"InvalidKeyError: {msg}")

class InvalidInputError(DCPEError):
    """Error with user-provided input data."""
    def __init__(self, msg="Invalid input"):
        super().__init__(f"InvalidInputError: {msg}")

class EncryptError(DCPEError):
    """Base class for encryption related errors."""
    def __init__(self, msg="Encryption error"):
        super().__init__(f"EncryptError: {msg}")

class DecryptError(DCPEError):
    """Base class for decryption related errors."""
    def __init__(self, msg="Decryption error"):
        super().__init__(f"DecryptError: {msg}")

class VectorEncryptError(EncryptError):
    """Errors specific to vector encryption."""
    def __init__(self, msg="Vector encryption error"):
        super().__init__(f"VectorEncryptError: {msg}")

class VectorDecryptError(DecryptError):
    """Errors specific to vector decryption."""
    def __init__(self, msg="Vector decryption error"):
        super().__init__(f"VectorDecryptError: {msg}")

class OverflowError(EncryptError):
    """Error due to numerical overflow during encryption."""
    def __init__(self, msg="Embedding or approximation factor too large"):
        super().__init__(f"OverflowError: {msg}")

class ProtobufError(DCPEError):
    """Error during Protobuf serialization or deserialization."""
    def __init__(self, msg="Protobuf error"):
        super().__init__(f"ProtobufError: {msg}")

class RequestError(DCPEError):
    """Error during a request to an external service (like TSP)."""
    def __init__(self, msg="Request error"):
        super().__init__(f"RequestError: {msg}")

class SerdeJsonError(DCPEError):
    """Error during JSON serialization or deserialization."""
    def __init__(self, msg="Serde JSON error"):
        super().__init__(f"SerdeJsonError: {msg}")

class TspError(DCPEError):
    """Error directly from the Tenant Security Proxy (TSP)."""
    def __init__(self, error_variant, http_code, tsp_code, msg="TSP error"):
        self.error_variant = error_variant # Store the error variant (e.g., string representation)
        self.http_code = http_code
        self.tsp_code = tsp_code
        super().__init__(f"TspError: {msg}, Variant: '{error_variant}', HTTP Code: {http_code}, TSP Code: {tsp_code}")