import { describe, it, expect, vi } from "vitest";
import { signJwt } from "../jwt";
import ReactNativeSiliconModule from "../../module";
import { createBridgeSuccess } from "../../__test_utils__/factories/bridge-result";

describe('signJwt()', () => {
    const jwtHeader = {
        typ: "JWT",
        randomKey: 12345
    };
    const jwtHeaderExpectedBase64Url = "eyJ0eXAiOiJKV1QiLCJyYW5kb21LZXkiOjEyMzQ1fQ"; // The actual Base64URl of the stringified JWT header
    
    const jwtPayload = {
        randomKey: 12345,
        anotherRandomKey: "some-data"
    };
    const jwtPayloadExpectedBase64Url = "eyJyYW5kb21LZXkiOjEyMzQ1LCJhbm90aGVyUmFuZG9tS2V5Ijoic29tZS1kYXRhIn0"; // The actual Base64URl of the stringified JWT payload

    // Dummy signature that is 'returned' from the native bridge (can be anything)
    const dummySignature = 'c29tZS1yYW5kb20tYmFzZTY0VXJs';
    
    // The expected return of signJwt() - header.payload.signature
    const expectedJwt = `${jwtHeaderExpectedBase64Url}.${jwtPayloadExpectedBase64Url}.${dummySignature}`;

    const mockSign = () => {
        // sign() expects ReactNativeSiliconModule.sign() to return a BridgeResult containing the signature
        const mockVal = createBridgeSuccess(dummySignature);
        vi.mocked(ReactNativeSiliconModule.sign).mockResolvedValue(mockVal);
    };

    it('should execute the full JWT generation lifecycle, transforming the header and payload into a fully signed token string encoded as Base64Url', async () => {
        mockSign();
        await expect(signJwt('some-random-alias', jwtHeader, jwtPayload, 'SHA256')).resolves.toBe(expectedJwt);
    });
});