import { DCPEError, InvalidKeyError, EncryptError } from "../exceptions/index.js";

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
});