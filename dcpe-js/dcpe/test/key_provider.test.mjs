import { ClientKeyProvider } from "../key_provider/index.js";

describe("Key Provider Module", () => {
    test("ClientKeyProvider should initialize with a key store", () => {
        const keyStore = {};
        const provider = new ClientKeyProvider(keyStore);
        expect(provider.keyStore).toBe(keyStore);
    });
});