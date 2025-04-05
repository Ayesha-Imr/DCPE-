// Base class for all exceptions
class DCPEError extends Error {
    /**
     * Initializes the base error with a default or provided message.
     * @param {string} message - The error message.
     */
    constructor(message = "An error occurred in the SDK") {
        super(message);
        this.name = "DCPEError";
    }
}

// Error while loading or with invalid configuration
class InvalidConfigurationError extends DCPEError {
    constructor(message = "Invalid configuration") {
        super(`InvalidConfigurationError: ${message}`);
        this.name = "InvalidConfigurationError";
    }
}

// Error with key used for encryption or decryption
class InvalidKeyError extends DCPEError {
    constructor(message = "Invalid key") {
        super(`InvalidKeyError: ${message}`);
        this.name = "InvalidKeyError";
    }
}

// Error with user-provided input data
class InvalidInputError extends DCPEError {
    constructor(message = "Invalid input") {
        super(`InvalidInputError: ${message}`);
        this.name = "InvalidInputError";
    }
}

// Base class for encryption-related errors
class EncryptError extends DCPEError {
    constructor(message = "Encryption error") {
        super(`EncryptError: ${message}`);
        this.name = "EncryptError";
    }
}

// Base class for decryption-related errors
class DecryptError extends DCPEError {
    constructor(message = "Decryption error") {
        super(`DecryptError: ${message}`);
        this.name = "DecryptError";
    }
}

// Errors specific to vector encryption
class VectorEncryptError extends EncryptError {
    constructor(message = "Vector encryption error") {
        super(`VectorEncryptError: ${message}`);
        this.name = "VectorEncryptError";
    }
}

// Errors specific to vector decryption
class VectorDecryptError extends DecryptError {
    constructor(message = "Vector decryption error") {
        super(`VectorDecryptError: ${message}`);
        this.name = "VectorDecryptError";
    }
}

// Error due to numerical overflow during encryption
class OverflowError extends EncryptError {
    constructor(message = "Embedding or approximation factor too large") {
        super(`OverflowError: ${message}`);
        this.name = "OverflowError";
    }
}

// Error during Protobuf serialization or deserialization
class ProtobufError extends DCPEError {
    constructor(message = "Protobuf error") {
        super(`ProtobufError: ${message}`);
        this.name = "ProtobufError";
    }
}

// Error during a request to an external service (like TSP)
class RequestError extends DCPEError {
    constructor(message = "Request error") {
        super(`RequestError: ${message}`);
        this.name = "RequestError";
    }
}

// Error during JSON serialization or deserialization
class SerdeJsonError extends DCPEError {
    constructor(message = "Serde JSON error") {
        super(`SerdeJsonError: ${message}`);
        this.name = "SerdeJsonError";
    }
}

// Error directly from the Tenant Security Proxy (TSP)
/**
 * Represents a TSP (Third-Party Service Provider) error.
 * This error extends the DCPEError class and includes additional
 * details specific to TSP-related issues.
 *
 * @class
 * @extends DCPEError
 * 
 * @param {string} errorVariant - The error variant, typically a string representation
 *                                that categorizes the type of error.
 * @param {number} httpCode - The HTTP status code associated with the error.
 * @param {number} tspCode - The TSP-specific error code providing additional context.
 * @param {string} [message="TSP error"] - A descriptive error message.
 */
class TspError extends DCPEError {
    /**
     * Initializes the TSP error with specific details.
     * @param {string} errorVariant - The error variant (e.g., string representation).
     * @param {number} httpCode - The HTTP status code.
     * @param {number} tspCode - The TSP-specific error code.
     * @param {string} message - The error message.
     */
    constructor(errorVariant, httpCode, tspCode, message = "TSP error") {
        super(`TspError: ${message}, Variant: '${errorVariant}', HTTP Code: ${httpCode}, TSP Code: ${tspCode}`);
        this.name = "TspError";
        this.errorVariant = errorVariant;
        this.httpCode = httpCode;
        this.tspCode = tspCode;
    }
}

// Export all error classes
export {
    DCPEError,
    InvalidConfigurationError,
    InvalidKeyError,
    InvalidInputError,
    EncryptError,
    DecryptError,
    VectorEncryptError,
    VectorDecryptError,
    OverflowError,
    ProtobufError,
    RequestError,
    SerdeJsonError,
    TspError
};