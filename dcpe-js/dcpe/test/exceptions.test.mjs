import { 
    DCPEError, 
    InvalidKeyError, 
    EncryptError,
    InvalidConfigurationError,
    InvalidInputError,
    DecryptError,
    VectorEncryptError,
    VectorDecryptError, 
    OverflowError,
    ProtobufError,
    RequestError,
    SerdeJsonError,
    TspError
} from "../exceptions/index.js";

describe("Exceptions Module", () => {
    test("DCPEError should have a default message", () => {
        const error = new DCPEError();
        expect(error.message).toBe("An error occurred in the SDK");
    });

    test("InvalidKeyError should extend DCPEError", () => {
        const error = new InvalidKeyError("Invalid key provided");
        expect(error.message).toBe("InvalidKeyError: Invalid key provided");
        expect(error).toBeInstanceOf(DCPEError);
    });

    test("EncryptError should extend DCPEError", () => {
        const error = new EncryptError("Encryption failed");
        expect(error.message).toBe("EncryptError: Encryption failed");
        expect(error).toBeInstanceOf(DCPEError);
    });
    test("InvalidConfigurationError should have correct message and inheritance", () => {
        const error = new InvalidConfigurationError("Bad config");
        expect(error.message).toBe("InvalidConfigurationError: Bad config");
        expect(error).toBeInstanceOf(DCPEError);
    });

    test("InvalidInputError should have correct message and inheritance", () => {
        const error = new InvalidInputError("Bad input");
        expect(error.message).toBe("InvalidInputError: Bad input");
        expect(error).toBeInstanceOf(DCPEError);
    });

    test("DecryptError should have correct message and inheritance", () => {
        const error = new DecryptError("Decryption failed");
        expect(error.message).toBe("DecryptError: Decryption failed");
        expect(error).toBeInstanceOf(DCPEError);
    });

    test("VectorEncryptError should inherit from EncryptError", () => {
        const error = new VectorEncryptError("Vector encryption failed");
        expect(error.message).toBe("VectorEncryptError: Vector encryption failed");
        expect(error).toBeInstanceOf(EncryptError);
        expect(error).toBeInstanceOf(DCPEError);
    });

    test("VectorDecryptError should inherit from DecryptError", () => {
        const error = new VectorDecryptError("Vector decryption failed");
        expect(error.message).toBe("VectorDecryptError: Vector decryption failed");
        expect(error).toBeInstanceOf(DecryptError);
        expect(error).toBeInstanceOf(DCPEError);
    });

    test("TspError should have custom properties", () => {
        const error = new TspError("AuthError", 401, 1001, "Authentication failed");
        expect(error.message).toBe("TspError: Authentication failed, Variant: 'AuthError', HTTP Code: 401, TSP Code: 1001");
        expect(error).toBeInstanceOf(DCPEError);
        expect(error.errorVariant).toBe("AuthError");
        expect(error.httpCode).toBe(401);
        expect(error.tspCode).toBe(1001);
    });

    test("Error classes should have default messages when not provided", () => {
        expect(new InvalidConfigurationError().message).toBe("InvalidConfigurationError: Invalid configuration");
        expect(new OverflowError().message).toBe("OverflowError: Embedding or approximation factor too large");
        expect(new ProtobufError().message).toBe("ProtobufError: Protobuf error");
        expect(new RequestError().message).toBe("RequestError: Request error");
        expect(new SerdeJsonError().message).toBe("SerdeJsonError: Serde JSON error");
    });
});