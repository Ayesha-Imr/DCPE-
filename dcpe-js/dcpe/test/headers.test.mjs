import { KeyIdHeader, EdekType, PayloadType } from "../headers/index.js";

describe("Headers Module", () => {
    test("KeyIdHeader should serialize and deserialize correctly", () => {
        const header = new KeyIdHeader(1, EdekType.STANDALONE, PayloadType.VECTOR_METADATA);
        const serialized = header.writeToBytes();
        const deserialized = KeyIdHeader.parseFromBytes(serialized);

        expect(deserialized.keyId).toBe(1);
        expect(deserialized.edekType).toBe(EdekType.STANDALONE);
        expect(deserialized.payloadType).toBe(PayloadType.VECTOR_METADATA);
    });
});