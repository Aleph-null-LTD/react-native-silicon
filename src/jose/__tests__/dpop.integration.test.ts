import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { test } from "@fast-check/vitest";
import fc from "fast-check";
import { generateDpopProof } from "../dpop";
import { SiliconError } from "../../errors";
import ReactNativeSiliconModule from "../../module";
import { createBridgeSuccess } from "../../__test_utils__/factories/bridge-result";
import { objectToBase64Url } from "../../utils/encoding";

describe('generateDpopProof()', () => { 
    const frozenDate = new Date();

    beforeAll(() => {
        // Freeze time
        vi.useFakeTimers();
        vi.setSystemTime(frozenDate);
    });

    afterAll(() => {
        // Resume using real time
        vi.useRealTimers();
    })

    it('should execute the full generation lifecycle of an RFC 9449 compliant, signed DPoP proof JWT', async () => {
        const dummyRandBytes = 'some-random-bytes';
        vi.mocked(
            ReactNativeSiliconModule.generateSecureRandomBytes
        ).mockResolvedValue(
            createBridgeSuccess(dummyRandBytes)
        );
        
        const dummyJwk = {
            alg: 'ES256',
            kty: 'EC',
            crv: 'P256',
            x: 'some-random-EC-X-coord',
            y: 'some-random-EC-Y-coord'
        };
        vi.mocked(
            ReactNativeSiliconModule.getJwk
        ).mockResolvedValue(
            createBridgeSuccess(dummyJwk)
        );
        
        const dummySignature = 'some-random-signature';
        vi.mocked(
            ReactNativeSiliconModule.sign
        ).mockResolvedValue(
            createBridgeSuccess(dummySignature)
        );

        // The JWT header should look like this
        const expectedJwtHeader = {
            typ: "dpop+jwt",
            alg: "ES256",
            jwk: {
                kty: "EC",
                crv: "P256",
                x: "some-random-EC-X-coord",
                y: "some-random-EC-Y-coord"
            }
        };

        // The JWT payload should look like this
        const expectedJwtPayload = {
            htu: "https://dummy.domain/some/path",
            htm: "POST",
            jti: "some-random-bytes",
            iat: Math.floor(Date.now() / 1000), // Time is frozen in the beforeAll so timestamp should be exactly the same
            nonce: "some-random-nonce"
        };

        await expect(
            generateDpopProof(
                'some-random-alias',
                {
                    htu: 'https://dummy.domain/some/path',
                    htm: 'POST',
                    digest: 'SHA256',
                    nonce: 'some-random-nonce',
                    // jti is NOT included - this will trigger the behaviour to generate secure random bytes
                }
            )
        ).resolves.toBe(
            `${objectToBase64Url(expectedJwtHeader)}.${objectToBase64Url(expectedJwtPayload)}.${dummySignature}`
        );
    });
});