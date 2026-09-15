import { describe, it, expect, vi } from "vitest";
import { test } from "@fast-check/vitest";
import fc from "fast-check";
import { generateDpopProof } from "../dpop";
import { signJwt } from "../jwt";
import { getJwk } from "../jwk";
import { generateSecureRandomBytes } from "../../core/random-generator";
import { SiliconError } from "../../errors";
import { isPlainObject } from "../../utils/validation";

vi.mock("../jwt");
vi.mock("../jwk");
vi.mock("../../core/random-generator");

describe('generateDpopProof()', () => {
    const setupMocks = () => {
        const dummyRandBytesStr = "some-random-bytes";
        vi.mocked(generateSecureRandomBytes).mockResolvedValue(dummyRandBytesStr);

        const dummyJwk = {
            alg: 'ES256',
            kty: 'EC',
            crv: 'P256',
            x: 'some-random-EC-X-coord',
            y: 'some-random-EC-Y-coord',
        };
        vi.mocked(getJwk).mockResolvedValue(dummyJwk);

        const dummyJwt = 'some-random-jwt';
        vi.mocked(signJwt).mockResolvedValue(dummyJwt);

        return {
            dummyJwt,
            dummyJwk,
            dummyRandBytesStr
        } as const;
    };
    
    it('should return successfully when all params are valid', async () => {
        const mockVals = setupMocks();
        
        await expect(
            generateDpopProof(
                'some-random-alias', 
                {
                    htu: 'https://dummy.domain/some/path',
                    htm: 'POST',
                    digest: 'SHA256',
                    nonce: 'some-random-nonce',
                    // jti is included - this will not trigger the behaviour to generate secure random bytes
                    jti: "some-random-jti"
                }
            )
        ).resolves.toBe(mockVals.dummyJwt);
        expect(generateSecureRandomBytes).toHaveBeenCalledTimes(0);
        expect(getJwk).toHaveBeenCalledOnce();
        expect(signJwt).toHaveBeenCalledOnce();
    });

    it('should generate a random jti by calling generateSecureRandomBytes() when opts.jti is not provided', async () => {
        const mockVals = setupMocks();
        
        await expect(
            generateDpopProof(
                'some-random-alias', 
                {
                    htu: 'https://dummy.domain/some/path',
                    htm: 'POST',
                    // jti is NOT included - this will trigger the default behaviour to generate secure random bytes
                }
            )
        ).resolves.toBe(mockVals.dummyJwt);
        expect(generateSecureRandomBytes).toHaveBeenCalledOnce();
        expect(getJwk).toHaveBeenCalledOnce();
        expect(signJwt).toHaveBeenCalledOnce();
    });

    it('should NOT generate a random jti when opts.jti is provided', async () => {
        const mockVals = setupMocks();
        
        await expect(
            generateDpopProof(
                'some-random-alias', 
                {
                    htu: 'https://dummy.domain/some/path',
                    htm: 'POST',
                    // jti is included - this will NOT trigger the default behaviour to generate secure random bytes
                    jti: 'some-random-jti'
                }
            )
        ).resolves.toBe(mockVals.dummyJwt);
        expect(generateSecureRandomBytes).toHaveBeenCalledTimes(0);
        expect(getJwk).toHaveBeenCalledOnce();
        expect(signJwt).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when alias is not a string, or is an empty string', async (chaoticData) => {
        const mockVals = setupMocks();

        if (typeof chaoticData == 'string' && chaoticData.trim().length > 0) {
            await expect(
                generateDpopProof(
                    chaoticData, 
                    {
                        htu: 'https://dummy.domain/some/path',
                        htm: 'POST',
                        // jti is NOT included - this will trigger the default behaviour to generate secure random bytes
                    }
                )
            ).resolves.toBe(mockVals.dummyJwt);
            expect(generateSecureRandomBytes).toHaveBeenCalledOnce();
            expect(getJwk).toHaveBeenCalledOnce();
            expect(signJwt).toHaveBeenCalledOnce();

        } else {
            await expect(
                generateDpopProof(
                    // @ts-expect-error - intentionally passing invalid value
                    chaoticData, 
                    {
                        htu: 'https://dummy.domain/some/path',
                        htm: 'POST',
                        // jti is NOT included - this will trigger the default behaviour to generate secure random bytes
                    }
                )
            ).rejects.instanceOf(SiliconError);
            expect(generateSecureRandomBytes).toHaveBeenCalledTimes(0);
            expect(getJwk).toHaveBeenCalledTimes(0);
            expect(signJwt).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything().filter((data) => !isPlainObject(data))],
        { numRuns: 1000 }
    )('should throw when opts is not a POJO', async (chaoticData) => {
        setupMocks();
        
        await expect(
            generateDpopProof(
                'some-random-alias', 
                // @ts-expect-error - intentionally passing invalid value
                chaoticData
            )
        ).rejects.instanceOf(SiliconError);
        expect(generateSecureRandomBytes).toHaveBeenCalledTimes(0);
        expect(getJwk).toHaveBeenCalledTimes(0);
        expect(signJwt).toHaveBeenCalledTimes(0);

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything().filter((data) => !isPlainObject(data))],
        { numRuns: 1000 }
    )('should throw when opts is not a POJO', async (chaoticData) => {
        setupMocks();
        
        await expect(
            generateDpopProof(
                'some-random-alias', 
                // @ts-expect-error - intentionally passing invalid value
                chaoticData
            )
        ).rejects.instanceOf(SiliconError);
        expect(generateSecureRandomBytes).toHaveBeenCalledTimes(0);
        expect(getJwk).toHaveBeenCalledTimes(0);
        expect(signJwt).toHaveBeenCalledTimes(0);

        vi.clearAllMocks();
    });

    test.prop(
        [
            fc.oneof(
                fc.constant('SHA256'),
                fc.constant('SHA384'),
                fc.constant('SHA512'),
                fc.constant(undefined),
                fc.anything()
            )
        ],
        { numRuns: 1000 }
    )('should throw when opts.digest is defined and not a valid string literal', async (chaoticData) => {
        const mockVals = setupMocks();

        if (chaoticData === 'SHA256' ||
            chaoticData === 'SHA384' ||
            chaoticData === 'SHA512' ||
            chaoticData === undefined
        ) {
            await expect(
                generateDpopProof(
                    'some-random-alias', 
                    {
                        digest: chaoticData,
                        htu: 'https://dummy.domain/some/path',
                        htm: 'POST',
                        // jti is NOT included - this will trigger the default behaviour to generate secure random bytes
                    }
                )
            ).resolves.toBe(mockVals.dummyJwt);
            expect(generateSecureRandomBytes).toHaveBeenCalledOnce();
            expect(getJwk).toHaveBeenCalledOnce();
            expect(signJwt).toHaveBeenCalledOnce();

        } else {
            await expect(
                generateDpopProof(
                    'some-random-alias', 
                    {
                        // @ts-expect-error - intentionally passing invalid value
                        digest: chaoticData,
                        htu: 'https://dummy.domain/some/path',
                        htm: 'POST',
                        // jti is NOT included - this will trigger the default behaviour to generate secure random bytes
                    }
                )
            ).rejects.instanceOf(SiliconError);
            expect(generateSecureRandomBytes).toHaveBeenCalledTimes(0);
            expect(getJwk).toHaveBeenCalledTimes(0);
            expect(signJwt).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [
            fc.oneof(
                fc.webUrl(),
                fc.anything()
            )
        ],
        { numRuns: 1000 }
    )('should throw when opts.htu is not a string, or is an empty string, or is not a valid URL', async (chaoticData) => {
        const mockVals = setupMocks();

        if (typeof chaoticData == 'string' && URL.canParse(chaoticData)) {
            await expect(
                generateDpopProof(
                    'some-random-alias', 
                    {
                        htu: chaoticData,
                        htm: 'POST',
                        // jti is NOT included - this will trigger the default behaviour to generate secure random bytes
                    }
                )
            ).resolves.toBe(mockVals.dummyJwt);
            expect(generateSecureRandomBytes).toHaveBeenCalledOnce();
            expect(getJwk).toHaveBeenCalledOnce();
            expect(signJwt).toHaveBeenCalledOnce();

        } else {
            await expect(
                generateDpopProof(
                    'some-random-alias', 
                    {
                        // @ts-expect-error - intentionally passing invalid value
                        htu: chaoticData,
                        htm: 'POST',
                        // jti is NOT included - this will trigger the default behaviour to generate secure random bytes
                    }
                )
            ).rejects.instanceOf(SiliconError);
            expect(generateSecureRandomBytes).toHaveBeenCalledTimes(0);
            expect(getJwk).toHaveBeenCalledTimes(0);
            expect(signJwt).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when opts.htm is not a string, or is an empty string', async (chaoticData) => {
        const mockVals = setupMocks();

        if (typeof chaoticData == 'string' && chaoticData.trim().length > 0) {
            await expect(
                generateDpopProof(
                    'some-random-alias', 
                    {
                        htu: 'https://dummy.domain/some/path',
                        htm: chaoticData,
                        // jti is NOT included - this will trigger the default behaviour to generate secure random bytes
                    }
                )
            ).resolves.toBe(mockVals.dummyJwt);
            expect(generateSecureRandomBytes).toHaveBeenCalledOnce();
            expect(getJwk).toHaveBeenCalledOnce();
            expect(signJwt).toHaveBeenCalledOnce();

        } else {
            await expect(
                generateDpopProof(
                    'some-random-alias', 
                    {
                        htu: 'https://dummy.domain/some/path',
                        // @ts-expect-error - intentionally passing invalid value
                        htm: chaoticData,
                        // jti is NOT included - this will trigger the default behaviour to generate secure random bytes
                    }
                )
            ).rejects.instanceOf(SiliconError);
            expect(generateSecureRandomBytes).toHaveBeenCalledTimes(0);
            expect(getJwk).toHaveBeenCalledTimes(0);
            expect(signJwt).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when opts.jti is defined and not a string, or is an empty string', async (chaoticData) => {
        const mockVals = setupMocks();

        if ((typeof chaoticData == 'string' && chaoticData.trim().length > 0) || chaoticData === undefined) {
            await expect(
                generateDpopProof(
                    'some-random-alias', 
                    {
                        htu: 'https://dummy.domain/some/path',
                        htm: "POST",
                        jti: chaoticData
                    }
                )
            ).resolves.toBe(mockVals.dummyJwt);
            
            if (chaoticData === undefined) {
                expect(generateSecureRandomBytes).toHaveBeenCalledOnce();
            } else {
                expect(generateSecureRandomBytes).toHaveBeenCalledTimes(0);
            }

            expect(getJwk).toHaveBeenCalledOnce();
            expect(signJwt).toHaveBeenCalledOnce();

        } else {
            await expect(
                generateDpopProof(
                    'some-random-alias', 
                    {
                        htu: 'https://dummy.domain/some/path',
                        htm: "POST",
                        // @ts-expect-error - intentionally passing invalid value
                        jti: chaoticData
                    }
                )
            ).rejects.instanceOf(SiliconError);
            expect(generateSecureRandomBytes).toHaveBeenCalledTimes(0);
            expect(getJwk).toHaveBeenCalledTimes(0);
            expect(signJwt).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when opts.nonce is defined and not a string, or is an empty string', async (chaoticData) => {
        const mockVals = setupMocks();

        if ((typeof chaoticData == 'string' && chaoticData.trim().length > 0) || chaoticData === undefined) {
            await expect(
                generateDpopProof(
                    'some-random-alias', 
                    {
                        htu: 'https://dummy.domain/some/path',
                        htm: "POST",
                        nonce: chaoticData
                    }
                )
            ).resolves.toBe(mockVals.dummyJwt);
            
            expect(generateSecureRandomBytes).toHaveBeenCalledOnce();
            expect(getJwk).toHaveBeenCalledOnce();
            expect(signJwt).toHaveBeenCalledOnce();

        } else {
            await expect(
                generateDpopProof(
                    'some-random-alias', 
                    {
                        htu: 'https://dummy.domain/some/path',
                        htm: "POST",
                        // @ts-expect-error - intentionally passing invalid value
                        nonce: chaoticData
                    }
                )
            ).rejects.instanceOf(SiliconError);

            // Will be called because opts.nonce is validated after the bytes are generated
            expect(generateSecureRandomBytes).toHaveBeenCalledOnce();
            
            expect(getJwk).toHaveBeenCalledTimes(0);
            expect(signJwt).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });
});
