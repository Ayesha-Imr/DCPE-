### File: `DCPE/exceptions_module.py`

**Overall Purpose:**
This file defines a hierarchy of custom exception classes specific to the DCPE framework. Its purpose is to provide more granular and informative error types than standard Python exceptions, allowing for better error handling and debugging throughout the searchable encryption processes. It establishes a common base error (`DCPEError`) and specialized errors for issues related to configuration, keys, input, encryption, decryption, and external interactions.

**Hierarchical Breakdown:**

*   **`DCPEError(Exception)`**: The base class for all custom exceptions within the DCPE framework.
    *   `__init__(self, message)`: Initializes the base error with a default or provided message.
    *   `__str__(self)`: Provides a standard string representation including the class name.
*   **`InvalidConfigurationError(DCPEError)`**: Raised when there's an issue with loading or validating framework configuration.
*   **`InvalidKeyError(DCPEError)`**: Raised for errors related to the encryption or decryption keys (e.g., incorrect format, insufficient length, zero scaling factor).
*   **`InvalidInputError(DCPEError)`**: Raised when user-provided input data is invalid (e.g., incorrect type, wrong format for headers).
*   **`EncryptError(DCPEError)`**: Base class for errors occurring during any encryption process.
    *   **`VectorEncryptError(EncryptError)`**: Specific errors during the encryption of vector embeddings.
    *   **`OverflowError(EncryptError)`**: Raised specifically when numerical overflow occurs during vector encryption, often due to large embedding values or approximation factors.
*   **`DecryptError(DCPEError)`**: Base class for errors occurring during any decryption process (e.g., authentication failure, incorrect key).
    *   **`VectorDecryptError(DecryptError)`**: Specific errors during the decryption of vector embeddings.
*   **`ProtobufError(DCPEError)`**: Raised for errors related to Protobuf serialization or deserialization (if used, though not explicitly shown in current dependencies).
*   **`RequestError(DCPEError)`**: Raised for errors during requests to external services (e.g., a Tenant Security Proxy, TSP).
*   **`SerdeJsonError(DCPEError)`**: Raised for errors during JSON serialization or deserialization (if used for specific internal operations).
*   **`TspError(DCPEError)`**: Represents errors originating directly from an external Tenant Security Proxy (TSP), capturing specific TSP error details.
    *   `__init__(self, error_variant, http_code, tsp_code, msg)`: Initializes with specific TSP error information.

**Dependencies & Interactions:**

*   **Depends on:** Standard Python `Exception`.
*   **Interacts with:** Almost all other modules in the `DCPE` directory (`crypto_module.py`, `headers_module.py`, `keys_module.py`, `rag_encryption_module.py`) import and raise these exceptions to signal specific error conditions.

---

### File: `DCPE/headers_module.py`

**Overall Purpose:**
This file defines structures and functions for creating, serializing, and parsing headers and metadata associated with encrypted data, particularly vector embeddings. It standardizes the format for packaging essential information like key identifiers, data types, initialization vectors (IVs), and authentication hashes alongside the ciphertext. This allows the decryption module to correctly identify the key and parameters needed to decrypt the data.

**Hierarchical Breakdown:**

*   **`EdekType(str, Enum)`**: Enumeration defining the type of Encrypted Data Encryption Key (EDEK) used. Values: `STANDALONE`, `SAAS_SHIELD`, `DATA_CONTROL_PLATFORM`.
*   **`PayloadType(str, Enum)`**: Enumeration defining the type of the encrypted payload. Values: `DETERMINISTIC_FIELD`, `VECTOR_METADATA`, `STANDARD_EDEK`.
*   **`KeyIdHeader`**: Class representing the header containing key identification and type information.
    *   `__init__(self, key_id: int, edek_type: EdekType, payload_type: PayloadType)`: Constructor validating input types and storing key ID and enum types.
    *   `create_header(cls, edek_type: EdekType, payload_type: PayloadType, key_id: int)`: Class method to conveniently create a `KeyIdHeader` instance.
    *   `write_to_bytes(self) -> bytes`: Serializes the header instance into a fixed 6-byte format (4 bytes key ID, 1 byte combined types, 1 byte padding).
    *   `parse_from_bytes(cls, header_bytes: bytes) -> 'KeyIdHeader'`: Class method to parse a 6-byte sequence back into a `KeyIdHeader` instance, performing validation.
    *   `_encode_type_byte(self) -> int`: Internal helper to pack `EdekType` and `PayloadType` into a single byte.
    *   `_decode_type_byte(cls, type_byte: int) -> Tuple[EdekType, PayloadType]`: Internal class method helper to unpack the type byte back into `EdekType` and `PayloadType` enums.
*   **`VectorMetadata(NamedTuple)`**: A simple named tuple structure to logically group the `key_id_header`, `iv` (bytes), and `auth_hash` (`AuthHash` object) for vector metadata.
*   **`encode_vector_metadata(key_id_header: KeyIdHeader, iv: bytes, auth_hash: AuthHash) -> bytes`**: Function to serialize a `KeyIdHeader`, IV, and `AuthHash` into a single byte string by concatenating their byte representations.
*   **`decode_version_prefixed_value(value_bytes: bytes) -> Tuple[KeyIdHeader, bytes]`**: Function to parse a byte string that is expected to start with a serialized `KeyIdHeader`. It extracts the header (assuming the fixed 6-byte length) and returns the parsed `KeyIdHeader` object along with the remaining bytes of the input string.

**Dependencies & Interactions:**

*   **Depends on:** `enum`, `typing` (standard libs), `DCPE.exceptions_module` (for `InvalidInputError`), `DCPE.crypto_module` (for `AuthHash` type).
*   **Interacts with:** `DCPE.rag_encryption_module` uses `KeyIdHeader`, `encode_vector_metadata`, and `decode_version_prefixed_value` to manage the metadata ("paired_icl_info") associated with encrypted vectors.

---

### File: `DCPE/key_provider_module.py`

**Overall Purpose:**
This file defines an abstraction layer for managing cryptographic keys, supporting the project's Bring Your Own Key (BYOK) principle. It provides an abstract base class (`KeyProvider`) that defines a standard interface for retrieving and storing keys. A concrete implementation (`FileKeyProvider`) is included as a simple example, storing keys in a local JSON file. This design allows the main encryption client to work with different key management systems (like external KMS) by simply providing a different implementation of the `KeyProvider` interface.

**Hierarchical Breakdown:**

*   **`KeyProvider(ABC)`**: Abstract Base Class defining the interface for all key providers.
    *   `get_key(self, key_id: str = None) -> bytes` (abstractmethod): Defines the method signature for retrieving raw key material, identified by an optional `key_id`. Must be implemented by subclasses.
    *   `store_key(self, key_material: bytes, key_id: str = None) -> str` (abstractmethod): Defines the method signature for storing raw key material, with an optional `key_id`. Returns the actual `key_id` used for storage. Must be implemented by subclasses.
*   **`FileKeyProvider(KeyProvider)`**: A concrete implementation of `KeyProvider` that uses a local JSON file for key storage.
    *   `__init__(self, key_file_path: str)`: Constructor that takes the path to the JSON key file and ensures the directory exists.
    *   `get_key(self, key_id: str = None) -> bytes`: Implements key retrieval. Reads the JSON file, looks for the specified `key_id` (or a default "key" if `key_id` is None), decodes the base64-encoded key, and returns the raw bytes. Raises `KeyError` if not found.
    *   `store_key(self, key_material: bytes, key_id: str = None) -> str`: Implements key storage. Loads existing keys from the JSON file, adds/updates the new key (base64 encoded) using the provided `key_id` (or "key" as default), and writes the updated data back to the file. Returns the `key_id`. Raises `RuntimeError` on failure.

**Dependencies & Interactions:**

*   **Depends on:** `abc`, `os`, `json`, `base64`, `typing` (standard libs).
*   **Interacts with:** `DCPE.rag_encryption_module` can be initialized with an instance of a `KeyProvider` implementation (like `FileKeyProvider`) to delegate key retrieval and potentially storage/rotation.

---

### File: `DCPE/keys_module.py`

**Overall Purpose:**
This file defines the core classes representing cryptographic keys and related parameters used within the DCPE framework. It provides structures for raw encryption keys (`EncryptionKey`), the scaling factor specific to DCPE vector encryption (`ScalingFactor`), and a composite key type for vectors (`VectorEncryptionKey`). It also includes utility functions for generating new random keys and deriving keys from secrets, centralizing key representation and basic key management operations.

**Hierarchical Breakdown:**

*   **`EncryptionKey`**: Represents a raw encryption key as a sequence of bytes.
    *   `__init__(self, key_bytes: bytes)`: Constructor, stores key bytes, includes type validation.
    *   `get_bytes(self)`: Returns the raw key bytes.
    *   `__eq__(self, other)`, `__repr__(self)`: Standard equality check and representation methods.
*   **`ScalingFactor`**: Represents the scaling factor (a float) used in the DCPE vector encryption algorithm.
    *   `__init__(self, factor: float)`: Constructor, stores the float factor, includes type validation.
    *   `get_factor(self)`: Returns the scaling factor value.
    *   `__eq__(self, other)`, `__repr__(self)`: Standard equality check and representation methods.
*   **`VectorEncryptionKey`**: Represents the combination of a `ScalingFactor` and an `EncryptionKey`, specifically required for DCPE vector encryption/decryption.
    *   `__init__(self, scaling_factor: ScalingFactor, key: EncryptionKey)`: Constructor, stores both components, includes type validation.
    *   `derive_from_secret(cls, secret: bytes, tenant_id: str, derivation_path: str)`: Class method to derive a `VectorEncryptionKey` deterministically from a master secret using HMAC-SHA512 with domain separation based on `tenant_id` and `derivation_path`. It then uses `unsafe_bytes_to_key` to construct the key.
    *   `unsafe_bytes_to_key(cls, key_bytes: bytes)`: Class method to construct a `VectorEncryptionKey` directly from a byte sequence (at least 35 bytes required). It splits the bytes into a 3-byte representation of the scaling factor and 32 bytes for the encryption key material. Raises `InvalidKeyError` if bytes are too short.
    *   `__eq__(self, other)`, `__repr__(self)`: Standard equality check and representation methods.
*   **`generate_random_key() -> EncryptionKey`**: Function that generates a cryptographically secure random 32-byte key and returns it as an `EncryptionKey` instance.

**Dependencies & Interactions:**

*   **Depends on:** `hashlib`, `secrets` (standard libs), `DCPE.exceptions_module` (for `InvalidKeyError`).
*   **Interacts with:**
    *   `DCPE.crypto_module`: Uses `VectorEncryptionKey`, `ScalingFactor`, and `EncryptionKey` extensively for vector encryption/decryption logic and hash computations.
    *   `DCPE.rag_encryption_module`: Uses `VectorEncryptionKey`, `EncryptionKey`, `ScalingFactor` to hold the keys for different encryption types (vector, text, deterministic) and uses `generate_random_key` (indirectly, via example or potentially key generation helper).


### File: `DCPE/crypto_module.py`

**Overall Purpose:**
This file serves as the cryptographic engine for the DCPE framework, implementing the core logic for Distance Comparison Preserving Encryption (DCPE) of vector embeddings. It handles the generation of cryptographic noise based on the provided keys and parameters, performs the actual encryption and decryption of vectors by adding/subtracting this noise, computes authentication hashes to ensure data integrity, and provides deterministic shuffling/unshuffling capabilities for lists based on an encryption key. It encapsulates the low-level mathematical and cryptographic operations required by higher-level modules.

**Hierarchical Breakdown:**

*   **Constants:**
    *   `SHUFFLE_KEY`: A hardcoded string used as part of the input for seeding the deterministic RNG in `create_rng_for_shuffle`, ensuring domain separation for the shuffling operation's key derivation.
*   **Classes:**
    *   **`AuthHash`**: Represents an authentication hash (specifically, a SHA-256 digest used for integrity).
        *   `__init__(self, hash_bytes: bytes)`: Initializes with 32 bytes, raising errors if the type or length is incorrect.
        *   `get_bytes(self)`: Returns the raw bytes of the hash.
        *   `__eq__(self, other)`: Compares two `AuthHash` objects based on their byte content.
        *   `__repr__(self)`: Provides a string representation.
    *   **`EncryptResult`**: A container class to bundle the results of a vector encryption operation.
        *   `__init__(self, ciphertext: List[float], iv: bytes, auth_hash: AuthHash)`: Initializes with the encrypted vector (ciphertext), the initialization vector (IV) used, and the calculated `AuthHash`.
        *   `__repr__(self)`: Provides a string representation.
*   **Functions:**
    *   **Noise Generation Helpers:**
        *   `sample_normal_vector(coin_rng: secrets.SystemRandom, message_dimensionality: int) -> np.ndarray`: Samples a vector from a standard multivariate normal distribution.
        *   `sample_uniform_point(coin_rng: secrets.SystemRandom) -> float`: Samples a uniform random float between 0 and 1.
        *   `calculate_uniform_point_in_ball(scaling_factor: ScalingFactor, approximation_factor: float, uniform_point: float, message_dimensionality: int) -> float`: Calculates a scaled point within an n-dimensional ball based on input parameters, determining the magnitude of the noise.
        *   `calculate_normalized_vector(multivariate_normal_sample: np.ndarray, uniform_point_in_ball: float) -> np.ndarray`: Normalizes the sampled normal vector and scales it by the `uniform_point_in_ball`.
        *   `generate_normalized_vector(key: VectorEncryptionKey, iv: bytes, approximation_factor: float, message_dimensionality: int) -> np.ndarray`: Orchestrates the generation of the final noise vector used in encryption/decryption. It uses the key, IV, and other parameters to deterministically (via seeding principles, although `secrets.SystemRandom` is used here for simplicity) generate the noise components through the helper functions above.
    *   **Vector Encryption/Decryption:**
        *   `encrypt_vector(key: VectorEncryptionKey, approximation_factor: float, message: List[float]) -> EncryptResult`: Encrypts a vector embedding. It generates a unique IV, calculates the deterministic noise using `generate_normalized_vector`, adds the noise to the scaled message (`key.scaling_factor * message`), computes an authentication hash using `compute_auth_hash`, and returns an `EncryptResult` containing the ciphertext, IV, and hash. Handles potential `OverflowError` and `InvalidKeyError`.
        *   `decrypt_vector(key: VectorEncryptionKey, approximation_factor: float, encrypted_result: EncryptResult) -> List[float]`: Decrypts an encrypted vector embedding. It first verifies the integrity using `check_auth_hash`. If valid, it regenerates the *exact same* noise vector using `generate_normalized_vector` (since the key, IV, and parameters are known). It then subtracts this noise from the ciphertext and divides by the scaling factor to recover the original message. Raises `DecryptError` on hash mismatch or `InvalidKeyError`.
    *   **Authentication:**
        *   `compute_auth_hash(key: VectorEncryptionKey, approximation_factor: float, iv: bytes, encrypted_embedding: np.ndarray) -> AuthHash`: Computes a SHA-256 hash over the key material, scaling factor, approximation factor, IV, and the bytes of the encrypted embedding elements. Returns the result as an `AuthHash` object. Uses `struct.pack` to convert float parameters to bytes consistently.
        *   `check_auth_hash(key: VectorEncryptionKey, approximation_factor: float, iv: bytes, encrypted_embedding: np.ndarray, auth_hash: AuthHash) -> bool`: Recomputes the authentication hash using `compute_auth_hash` with the provided inputs and compares it to the given `auth_hash`. Returns `True` if they match, `False` otherwise.
    *   **Deterministic Shuffling:**
        *   `create_rng_for_shuffle(key: EncryptionKey)`: Creates a deterministic pseudo-random number generator (PRNG). It uses HMAC-SHA256 with the `SHUFFLE_KEY` constant and the provided `key` to derive a seed. This seed is used with AES-CTR (with a fixed nonce) to generate a stream of pseudo-random bytes, which are then converted to floats by the nested `CryptographicRandom` class. This ensures the sequence of random numbers is repeatable for the same input `key`.
        *   `shuffle(key: EncryptionKey, input_list: list) -> list`: Deterministically shuffles the `input_list`. It uses `create_rng_for_shuffle` to get a deterministic RNG and sorts the list based on the pseudo-random numbers generated for each element.
        *   `unshuffle(key: EncryptionKey, input_list: list) -> list`: Deterministically reverses the shuffling performed by `shuffle`. It recreates the *same* deterministic RNG using `create_rng_for_shuffle`. By pairing the shuffled elements with their corresponding generated random numbers and tracking original indices, it reconstructs the original order of the list.

**Dependencies & Interactions:**

*   **Depends on:**
    *   Standard Libraries: `numpy` (for vector math), `secrets` (for IV generation, RNG seeding), `hashlib` (for SHA-256), `struct` (for float-to-byte conversion), `typing`.
    *   `cryptography` library: For `hmac`, `hashes`, `Cipher`, `algorithms`, `modes` used in `create_rng_for_shuffle`.
    *   Local Modules: `DCPE.exceptions_module` (for `DecryptError`, `InvalidKeyError`, `OverflowError`), `DCPE.keys_module` (for `VectorEncryptionKey`, `ScalingFactor`, `EncryptionKey` types).
*   **Interacts with:**
    *   `DCPE.rag_encryption_module`: This module is the primary user, calling `encrypt_vector`, `decrypt_vector`, `shuffle`, and `unshuffle` to perform high-level encryption/decryption and shuffling operations.
    *   `DCPE.headers_module`: Defines the `AuthHash` type which is used by `headers_module` within its `VectorMetadata` structure and encoding/decoding functions.


### File: `DCPE/rag_encryption_module.py`

**Overall Purpose:**
This file defines the `RagEncryptionClient`, which serves as the primary high-level interface for the DCPE searchable encryption framework. It orchestrates the encryption and decryption of different data types required in a Retrieval-Augmented Generation (RAG) context: vector embeddings (using DCPE with shuffling), chunk text (using standard AES-GCM), and metadata fields (using deterministic AES-GCM-SIV). It integrates key management, allowing keys to be provided directly or via a `KeyProvider`, and wraps the lower-level cryptographic operations from `crypto_module` and the `cryptography` library, providing a unified API for securing RAG data components according to Zero-Trust principles.

**Hierarchical Breakdown:**

*   **`RagEncryptionClient`**: The main client class for performing encryption and decryption operations.
    *   **`__init__(self, encryption_key: bytes = None, approximation_factor: float = 1.0, key_provider = None, key_id: str = None)`**:
        *   Initializes the client. Requires either raw `encryption_key` bytes or a `key_provider` instance and a `key_id`.
        *   Validates input types and key length.
        *   Stores the `approximation_factor` for vector encryption.
        *   Initializes internal key objects (`VectorEncryptionKey`, `EncryptionKey`) for vector, text, and deterministic encryption based on the provided master key material.
        *   Stores `key_provider` and `key_id` if used.
    *   **`rotate_key(self, new_key_material: bytes = None, new_key_id: str = None)`**:
        *   Allows updating the client's active encryption key. Requires either new raw `new_key_material` or a `new_key_id` to fetch from the `key_provider`.
        *   Stores the previous keys (for potential backward compatibility, though decryption using old keys isn't explicitly implemented here).
        *   Updates the client's internal `vector_encryption_key`, `text_encryption_key`, and `deterministic_encryption_key` with the new key material.
    *   **`encrypt_vector(self, plaintext_vector: List[float]) -> Tuple[List[float], bytes]`**:
        *   Encrypts a vector embedding using DCPE with an added shuffling step.
        *   Inputs: Plaintext vector (list of floats).
        *   Steps:
            1.  Deterministically shuffles the input vector using `crypto_module.shuffle`.
            2.  Encrypts the *shuffled* vector using `crypto_module.encrypt_vector`.
            3.  Creates a `KeyIdHeader` and encodes it with the IV and AuthHash from the encryption result into `paired_icl_info` bytes using `headers_module`.
        *   Outputs: A tuple containing the encrypted vector (list of floats) and the encoded metadata bytes (`paired_icl_info`).
    *   **`decrypt_vector(self, encrypted_vector: List[float], paired_icl_info: bytes) -> List[float]`**:
        *   Decrypts an encrypted vector embedding that was encrypted by `encrypt_vector`.
        *   Inputs: Encrypted vector (list of floats), encoded metadata bytes (`paired_icl_info`).
        *   Steps:
            1.  Decodes `paired_icl_info` using `headers_module` to extract the IV and AuthHash.
            2.  Decrypts the vector using `crypto_module.decrypt_vector`, yielding the *shuffled* plaintext.
            3.  Deterministically unshuffles the decrypted vector using `crypto_module.unshuffle` to restore the original order.
        *   Outputs: The original plaintext vector (list of floats).
    *   **`encrypt_text(self, plaintext: str) -> Tuple[bytes, bytes, bytes]`**:
        *   Encrypts standard text content using AES-GCM for confidentiality and integrity.
        *   Inputs: Plaintext string.
        *   Steps: Generates a random 12-byte IV, performs AES-GCM encryption using `text_encryption_key`.
        *   Outputs: A tuple containing the ciphertext (bytes), the IV (bytes), and the authentication tag (bytes).
    *   **`decrypt_text(self, encrypted_text: bytes, iv: bytes, tag: bytes) -> str`**:
        *   Decrypts text encrypted by `encrypt_text`.
        *   Inputs: Ciphertext (bytes), IV (bytes), authentication tag (bytes).
        *   Steps: Performs AES-GCM decryption using `text_encryption_key`, verifying the IV and tag. Raises `DecryptError` on failure.
        *   Outputs: The original plaintext string.
    *   **`encrypt_deterministic_text(self, plaintext: str) -> bytes`**:
        *   Encrypts text deterministically (same input yields same output) while maintaining confidentiality and integrity, suitable for searchable metadata fields.
        *   Inputs: Plaintext string.
        *   Steps:
            1.  Derives a specific key using HKDF from `deterministic_encryption_key`.
            2.  Derives a deterministic nonce from the plaintext using HMAC-SHA256.
            3.  Encrypts using AES-GCM-SIV with the derived key and nonce.
            4.  Prepends the nonce to the ciphertext.
        *   Outputs: Combined nonce and ciphertext bytes.
    *   **`decrypt_deterministic_text(self, encrypted_data: bytes) -> str`**:
        *   Decrypts text encrypted by `encrypt_deterministic_text`.
        *   Inputs: Combined nonce and ciphertext bytes.
        *   Steps: Extracts nonce and ciphertext, re-derives the key using HKDF, performs AES-GCM-SIV decryption. Raises `DecryptError` on failure.
        *   Outputs: The original plaintext string.
*   **Helper Classes:** (Primarily data structures)
    *   **`PlaintextVector`**: Simple container for a plaintext vector (list of floats).
    *   **`EncryptedVector`**: Simple container for an encrypted vector (list of floats) and its associated `paired_icl_info` (bytes).

**Dependencies & Interactions:**

*   **Depends on:**
    *   Standard Libraries: `numpy`, `secrets`, `os`, `json`, `base64`, `hmac`, `typing`.
    *   `cryptography` library: For AES-GCM, AES-GCM-SIV, HKDF, SHA256, HMAC primitives.
    *   Local Modules:
        *   `DCPE.crypto_module`: For core vector encryption (`encrypt_vector`, `decrypt_vector`), authentication (`AuthHash`, `EncryptResult`), and shuffling (`shuffle`, `unshuffle`).
        *   `DCPE.keys_module`: For key representation (`VectorEncryptionKey`, `EncryptionKey`, `ScalingFactor`).
        *   `DCPE.headers_module`: For metadata handling (`KeyIdHeader`, `EdekType`, `PayloadType`, `encode_vector_metadata`, `decode_version_prefixed_value`).
        *   `DCPE.exceptions_module`: For raising specific errors (`DecryptError`, `TypeError`, `ValueError`).
        *   `DCPE.key_provider_module`: To interact with the `KeyProvider` interface for key management.
*   **Interacts with:**
    *   External Code (e.g., `Vector_Search_Pipelines/encrypted_vector_search.py`): This client is designed to be instantiated and used by applications needing to encrypt/decrypt data for the secure RAG pipeline. It provides the primary API for these operations.


### File: `DCPE/example_usage.py`

**Overall Purpose:**
This file serves as a practical demonstration and basic test suite for the core functionalities provided by the `RagEncryptionClient`. Its purpose is to illustrate how to initialize the client, generate keys, and perform roundtrip encryption and decryption for the different data types supported by the framework: vector embeddings (DCPE), standard text (AES-GCM), and deterministic text (AES-ECB in this example, though the main client uses AES-GCM-SIV). It acts as a usage guide and a simple integration test to verify that the encryption and decryption processes work correctly together.

**Hierarchical Breakdown:**

*   **`main()`**: The primary function containing the example usage logic.
    *   **1. Key Generation**:
        *   Calls `keys_module.generate_random_key()` to create a raw 32-byte encryption key.
        *   Defines an example `approximation_factor` for vector encryption.
    *   **2. Client Initialization**:
        *   Instantiates `RagEncryptionClient` from `rag_encryption_module`, providing the generated key and approximation factor.
    *   **3. Vector Encryption and Decryption Roundtrip**:
        *   Defines a sample `PlaintextVector`.
        *   Calls `rag_client.encrypt_vector()` to encrypt the vector.
        *   Prints the original, encrypted vector (partial), and paired ICL info (partial).
        *   Calls `rag_client.decrypt_vector()` to decrypt the result.
        *   Prints the decrypted vector (partial).
        *   Uses `numpy.testing.assert_array_almost_equal` to verify that the decrypted vector is close to the original (accounting for DCPE approximation).
    *   **4. Standard Text Encryption and Decryption Roundtrip (AES-GCM)**:
        *   Defines sample plaintext text.
        *   Calls `rag_client.encrypt_text()` to encrypt the text, capturing ciphertext, IV, and tag.
        *   Prints original text, ciphertext (partial), IV, and tag.
        *   Calls `rag_client.decrypt_text()` with ciphertext, IV, and tag.
        *   Prints the decrypted text.
        *   Uses `assert` to verify the decrypted text matches the original exactly.
    *   **5. Deterministic Text Encryption and Decryption Roundtrip (AES-ECB - Demo Only)**:
        *   Defines sample deterministic plaintext.
        *   Calls `rag_client.encrypt_deterministic_text()` (Note: The example uses the name matching the client method, but the comment indicates it might be demonstrating an older/simpler ECB approach for the example, while the actual client implements AES-GCM-SIV).
        *   Prints original text and ciphertext (partial).
        *   Calls `rag_client.decrypt_deterministic_text()`.
        *   Prints the decrypted text.
        *   Uses `assert` to verify the decrypted text matches the original exactly.
    *   **Error Handling**:
        *   Includes a `try...except` block to catch potential `DCPEError` exceptions from the client operations and general `Exception` types, printing informative error messages.
*   **Script Execution Block (`if __name__ == "__main__":`)**: Ensures the `main()` function is called when the script is executed directly.

**Dependencies & Interactions:**

*   **Depends on:**
    *   Standard Libraries: `numpy` (for vector comparison).
    *   Local Modules:
        *   `DCPE.rag_encryption_module`: Imports `RagEncryptionClient` and `PlaintextVector`.
        *   `DCPE.keys_module`: Imports `generate_random_key`.
        *   `DCPE.exceptions_module`: Imports `DCPEError` for exception handling.
*   **Interacts with:**
    *   `DCPE.rag_encryption_module`: Creates an instance of `RagEncryptionClient` and calls its `encrypt_vector`, `decrypt_vector`, `encrypt_text`, `decrypt_text`, `encrypt_deterministic_text`, and `decrypt_deterministic_text` methods.
    *   `DCPE.keys_module`: Calls `generate_random_key()` to obtain a key for the client.
    *   `DCPE.exceptions_module`: Catches exceptions defined in this module.



### File: `Vector_Search_Pipelines/encrypted_vector_search.py`

**Overall Purpose:**
This script implements a complete pipeline for secure Retrieval-Augmented Generation (RAG) data processing and vector search, leveraging the DCPE framework for end-to-end encryption. It demonstrates how to ingest documents (from URLs), process them into chunks, generate embeddings (using Cohere), encrypt the text chunks, metadata, and vector embeddings using the `RagEncryptionClient`, store the encrypted data in a Milvus vector database, and perform secure vector searches (including metadata filtering) on the encrypted data. The search queries are encrypted client-side, and the results retrieved from Milvus are decrypted client-side, ensuring data remains confidential even within the vector database.

**Hierarchical Breakdown:**

*   **Imports & Setup:**
    *   Imports necessary libraries (`os`, `time`, `json`, `base64`, `numpy`, `dotenv`, `pymilvus`, `langchain_text_splitters`, `cohere`, `docling`).
    *   Imports the `RagEncryptionClient` from the local `DCPE` module.
    *   Loads environment variables (`COHERE_API_KEY`, `ZILLIZ_ENDPOINT`, `ZILLIZ_TOKEN`) using `dotenv`.
    *   Defines the key file path (`KEY_FILE`) and approximation factor.
    *   Initializes the `RagEncryptionClient` with a key (potentially loaded/created via a helper method not shown but implied by `get_or_create_encryption_key`) and the approximation factor.
    *   Initializes clients for Cohere (`cohere_client`) and Milvus/Zilliz (`MilvusClient`, `Collection`).
    *   Connects to Zilliz Cloud and loads the target collection.
*   **Data Processing Functions:**
    *   `extract_pdf_url(document_url)`: Uses `docling` to extract text content from a PDF document specified by a URL.
    *   `get_embeddings(text)`: Uses the Cohere API (`cohere_client.embed`) to generate a vector embedding for a given text chunk (document type).
    *   `chunk(text)`: Uses `langchain_text_splitters` (`RecursiveCharacterTextSplitter`) to split long text into smaller chunks.
    *   `get_query_embedding(query)`: Uses the Cohere API to generate a vector embedding specifically for a search query (query type).
*   **Data Encryption & Ingestion:**
    *   `process_data(data, source_url, rag_client)`: Takes raw text data and its source URL, processes it for ingestion:
        1.  Chunks the text using `chunk()`.
        2.  For each chunk:
            *   Encrypts the chunk text using `rag_client.encrypt_text()` (AES-GCM).
            *   Concatenates IV, Tag, and Ciphertext, then Base64 encodes the result for storage.
            *   Deterministically encrypts metadata (`source_url`, current date) using `rag_client.encrypt_deterministic_text()` and Base64 encodes them.
            *   Generates embedding using `get_embeddings()`.
            *   Encrypts the embedding using `rag_client.encrypt_vector()` (DCPE).
            *   Creates a dictionary containing the encrypted/encoded fields (`source_url`, `chunk_text`, `upload_date`, `vector`).
        3.  Returns a list of these dictionaries.
    *   `process_and_ingest_data(url, rag_client)`: Orchestrates ingestion:
        1.  Extracts text from the URL using `extract_pdf_url()`.
        2.  Processes the extracted text using `process_data()`.
        3.  Inserts the resulting list of encrypted data dictionaries into the Milvus collection using `client.insert()`.
*   **Search & Decryption Functions:**
    *   `format_search_results(search_results, rag_client)`: Takes raw search results from Milvus and decrypts the relevant fields for presentation:
        1.  Iterates through hits in `search_results`.
        2.  Retrieves Base64 encoded encrypted `chunk_text`, `source_url`, and `upload_date` from the hit entity.
        3.  Base64 decodes the `source_url` and `upload_date`, then decrypts them using `rag_client.decrypt_deterministic_text()`. Includes robust error handling and padding fixes for Base64.
        4.  Base64 decodes the `chunk_text` payload, extracts IV, tag, and ciphertext, then decrypts using `rag_client.decrypt_text()`. Includes error handling.
        5.  Formats the decrypted text, source URL, upload date, and similarity score into a readable string.
        6.  Returns the combined formatted string for all results.
    *   `perform_single_vector_search(query_embedding, rag_client)`: Performs a simple vector search:
        1.  Encrypts the raw `query_embedding` using `rag_client.encrypt_vector()`.
        2.  Performs a search (`collection.search`) against the `vector` field in Milvus using the encrypted query embedding and COSINE metric. Specifies output fields to retrieve.
        3.  Formats the results using `format_search_results()`.
    *   `search_query(query, rag_client)`: A convenience function to handle search end-to-end:
        1.  Gets the query embedding using `get_query_embedding()`.
        2.  Performs the search using `perform_single_vector_search()`.
        3.  Returns the formatted results.
*   **Metadata Filtering Functions:**
    *   `_process_filter_template(expr, params, rag_client)`: Helper to process filter expressions with placeholders. It encrypts the string values in the `params` dictionary using `rag_client.encrypt_deterministic_text()` and Base64 encodes them before substituting them into the `expr` template. Handles lists for the 'IN' operator.
    *   `_build_filter_expression(filters, logic="AND", rag_client=None)`: Helper to construct a Milvus filter expression string from a list of structured filter conditions (`field`, `op`, `value`). It encrypts string values using `rag_client.encrypt_deterministic_text()` and Base64 encodes them before incorporating them into the expression. Handles various operators like `==`, `IN`, and converts `LIKE` to exact match (`==`) due to deterministic encryption limitations. Combines conditions using the specified logic (`AND`/`OR`).
    *   `search_with_metadata_filter(query, filter_options, rag_client)`: Performs vector search with metadata filtering:
        1.  Gets and encrypts the query embedding.
        2.  Builds the Milvus search parameters (`data`, `anns_field`, `param`, `limit`, `output_fields`).
        3.  Processes the `filter_options`:
            *   If `expr` and `params` are provided, uses `_process_filter_template` to create the filter string.
            *   If `filters` list is provided, uses `_build_filter_expression` to create the filter string.
        4.  Adds the generated filter expression (`expr`) to the search parameters.
        5.  Executes the search (`collection.search`) with the filter.
        6.  Formats the results using `format_search_results()`.

**Dependencies & Interactions:**

*   **Depends on:**
    *   External Libraries: `os`, `time`, `json`, `base64`, `numpy`, `python-dotenv`, `pymilvus`, `langchain-text-splitters`, `cohere`, `docling`.
    *   Local Modules: `DCPE.rag_encryption_module` (imports `RagEncryptionClient`).
*   **Interacts with:**
    *   `DCPE.rag_encryption_module`: Instantiates `RagEncryptionClient` and heavily uses its methods (`encrypt_vector`, `decrypt_vector`, `encrypt_text`, `decrypt_text`, `encrypt_deterministic_text`, `decrypt_deterministic_text`) for all cryptographic operations.
    *   Cohere API: Uses `cohere.Client` to generate embeddings for documents and queries.
    *   Zilliz Cloud / Milvus: Uses `pymilvus.MilvusClient` and `pymilvus.Collection` to connect, insert encrypted data, and perform searches on the encrypted vectors and metadata.
    *   Environment: Reads API keys and endpoints from environment variables (`.env` file).
    *   Filesystem: Reads the encryption key from `KEY_FILE` (via the implied `get_or_create_encryption_key` mechanism).
