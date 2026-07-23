import { describe, it, expect, vi } from "vitest";
import { createBridgeFailure, createBridgeSuccess } from "../../../__test_utils__/factories/bridge-result";
import { sign, verify } from '../operations';
import ReactNativeSiliconModule from '../../../module';
import fc from 'fast-check';
import { test } from '@fast-check/vitest';
import { SiliconError, SiliconErrorCode } from "../../../errors";
import { isPlainObject } from "../../../utils/validation";

describe('sign()', () => {
    const defaultMockData = "some random signature";
    const defaultMockVal = createBridgeSuccess(defaultMockData);
    vi.mocked(ReactNativeSiliconModule.sign).mockResolvedValue(defaultMockVal);

    it('should successfully return a string when valid params are provided', async () => {
        await expect(
            sign(
                'some-random-alias', 
                new Uint8Array([10, 20, 30]), 
                {
                    encoding: 'B64',
                    digest: 'SHA256',
                    format: 'DER'
                }
            )
        ).resolves.toBe(defaultMockData);
        expect(ReactNativeSiliconModule.sign).toHaveBeenCalledOnce();
    });

    it('should throw when the bridge returns a failure result', async () => {
        const mockFailVal = createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, 'test error message', 'some-random-error-stack');
        vi.mocked(ReactNativeSiliconModule.sign).mockResolvedValueOnce(mockFailVal);

        let didThrow = true;
        try {
            await sign(
                'some-random-alias',
                new Uint8Array([10, 20, 30]), 
                {
                    encoding: 'B64',
                    digest: 'SHA256',
                    format: 'DER'
                }
            );
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) expect.fail('expected sign to throw, but it did not');

        expect(ReactNativeSiliconModule.sign).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when alias is not a string or is an empty string', async (chaoticData) => {
        const isValid = typeof chaoticData == 'string' && chaoticData.trim().length > 0

        if (isValid) {
            await expect(
                sign(
                    chaoticData, 
                    new Uint8Array([10, 20, 30]), 
                    {
                        encoding: 'B64',
                        digest: 'SHA256',
                        format: 'DER'
                    }
                )
            ).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.sign).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                await sign(
                    // @ts-expect-error
                    chaoticData, 
                    new Uint8Array([10, 20, 30]), 
                    {
                        encoding: 'B64',
                        digest: 'SHA256',
                        format: 'DER'
                    }
                );
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected sign to throw, but it did not');

            expect(ReactNativeSiliconModule.sign).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when payload is not a string and not a Uint8Array', async (chaoticData) => {
        const isValid = (typeof chaoticData == 'string' && chaoticData.trim().length > 0) || chaoticData instanceof Uint8Array;

        if (isValid) {
            await expect(
                sign(
                    'some-random-alias', 
                    chaoticData,
                    {
                        encoding: 'B64',
                        digest: 'SHA256',
                        format: 'DER'
                    }
                )
            ).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.sign).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                await sign(
                    'some-random-alias', 
                    // @ts-expect-error
                    chaoticData,
                    {
                        encoding: 'B64',
                        digest: 'SHA256',
                        format: 'DER'
                    }
                );
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected sign to throw, but it did not');

            expect(ReactNativeSiliconModule.sign).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    const nonObjectChaoticData = fc.anything(
    ).filter(
        (data) => {
            if (isPlainObject(data)) return false;
            if (data === undefined) return false;
            return true;
        }
    );
    test.prop(
        [nonObjectChaoticData],
        { numRuns: 1000 }
    )('should throw when opts is not an object', async (chaoticData) => {
        
        let didThrow = true;
        try {
            await sign(
                'some-random-alias', 
                new Uint8Array([10, 20, 30]),
                // @ts-expect-error
                chaoticData
            );
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) expect.fail('expected sign to throw, but it did not');

        expect(ReactNativeSiliconModule.sign).toHaveBeenCalledTimes(0);

        vi.clearAllMocks();
    });

    test.prop(
        [   
            fc.oneof(
                fc.constant('B64'),
                fc.constant('B64URL'),
                fc.constant(undefined),
                fc.anything()
            )
        ],
        { numRuns: 1000 }
    )('should throw when opts.encoding is defined and not a valid string literal', async (chaoticData) => {
        if (chaoticData === 'B64' || chaoticData === 'B64URL' || chaoticData === undefined) {
            await expect(
                sign(
                    'some-random-alias', 
                    new Uint8Array([10, 20, 30]),
                    {
                        encoding: chaoticData,
                        digest: 'SHA256',
                        format: 'DER'
                    }
                )
            ).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.sign).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                await sign(
                    'some-random-alias', 
                    new Uint8Array([10, 20, 30]),
                    {
                        // @ts-expect-error
                        encoding: chaoticData,
                        digest: 'SHA256',
                        format: 'DER'
                    }
                );
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected sign to throw, but it did not');

            expect(ReactNativeSiliconModule.sign).toHaveBeenCalledTimes(0);
        }

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
        if (chaoticData === 'SHA256' || chaoticData === 'SHA384' || chaoticData === 'SHA512' || chaoticData === undefined) {
            await expect(
                sign(
                    'some-random-alias', 
                    new Uint8Array([10, 20, 30]),
                    {
                        encoding: 'B64',
                        digest: chaoticData,
                        format: 'DER'
                    }
                )
            ).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.sign).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                await sign(
                    'some-random-alias', 
                    new Uint8Array([10, 20, 30]),
                    {
                        encoding: 'B64',
                        // @ts-expect-error
                        digest: chaoticData,
                        format: 'DER'
                    }
                );
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected sign to throw, but it did not');

            expect(ReactNativeSiliconModule.sign).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [
            fc.oneof(
                fc.constant('DER'),
                fc.constant('P1363'),
                fc.constant(undefined),
                fc.anything()
            )
        ],
        { numRuns: 1000 }
    )('should throw when opts.format is defined and not a valid string literal', async (chaoticData) => {
        if (chaoticData === 'DER' || chaoticData === 'P1363' || chaoticData === undefined) {
            await expect(
                sign(
                    'some-random-alias', 
                    new Uint8Array([10, 20, 30]),
                    {
                        encoding: 'B64',
                        digest: 'SHA256',
                        format: chaoticData
                    }
                )
            ).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.sign).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                await sign(
                    'some-random-alias', 
                    new Uint8Array([10, 20, 30]),
                    {
                        encoding: 'B64',
                        digest: 'SHA256',
                        // @ts-expect-error
                        format: chaoticData
                    }
                );
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected sign to throw, but it did not');

            expect(ReactNativeSiliconModule.sign).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });
});

describe('verify()', () => {
    const defaultMockData = true;
    const defaultMockVal = createBridgeSuccess(defaultMockData);
    vi.mocked(ReactNativeSiliconModule.verify).mockResolvedValue(defaultMockVal);

    const validPayload = new Uint8Array([10, 20, 30]);
    const validSignature = 'some-random-signature';
    const validOpts = {
        alias: 'some-random-alias',
        algorithm: 'ES256'
    } as const;

    it('should successfully return a boolean when valid params are provided', async () => {
        await expect(verify(validPayload, validSignature, validOpts)).resolves.toBe(defaultMockData);

        expect(ReactNativeSiliconModule.verify).toHaveBeenCalledOnce();
    });

    it('should throw when bridge returns a failure result', async () => {
        const mockVal = createBridgeFailure(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, 'some random error message', 'some-random-error-stack');
        vi.mocked(ReactNativeSiliconModule.verify).mockResolvedValueOnce(mockVal);

        let didThrow = true;
        try {
            await verify(validPayload, validSignature, validOpts);
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) expect.fail('expected verify() to throw, but it did not');

        expect(ReactNativeSiliconModule.verify).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when payload is not a string and not a Uint8Array', async (chaoticData) => {
        if ((typeof chaoticData == 'string' && chaoticData.trim().length > 0) ||
            chaoticData instanceof Uint8Array
        ) {
            await expect(verify(chaoticData, validSignature, validOpts)).resolves.toBe(defaultMockData)
            expect(ReactNativeSiliconModule.verify).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await verify(chaoticData, validSignature, validOpts);
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected verify() to throw, but it did not');

            expect(ReactNativeSiliconModule.verify).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when signature is not a string or is an empty string', async (chaoticData) => {
        if (typeof chaoticData == 'string' && chaoticData.trim().length > 0) {
            await expect(verify(validPayload, chaoticData, validOpts)).resolves.toBe(defaultMockData)
            expect(ReactNativeSiliconModule.verify).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await verify(validPayload, chaoticData, validOpts);
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected verify() to throw, but it did not');

            expect(ReactNativeSiliconModule.verify).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [
            fc.anything(
            ).filter(
                (data) => {
                    if (isPlainObject(data)) return false;
                    return true;
                }
            )
        ],
        { numRuns: 1000 }
    )('should throw when opts is not a POJO', async (chaoticData) => {
        let didThrow = true;
        try {
            // @ts-expect-error
            await verify(validPayload, validSignature, chaoticData);
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) expect.fail('expected verify() to throw, but it did not');

        expect(ReactNativeSiliconModule.verify).toHaveBeenCalledTimes(0);

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when opts.alias is not a string and is not empty (for internal keys)', async (chaoticData) => {
        if (typeof chaoticData == 'string' && chaoticData.trim().length > 0) {
            await expect(
                verify(
                    validPayload, 
                    validSignature, 
                    {
                        alias: chaoticData
                    }
                )
            ).resolves.toBe(defaultMockData)
            expect(ReactNativeSiliconModule.verify).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                await verify(
                    validPayload, 
                    validSignature, 
                    {
                        // @ts-expect-error
                        alias: chaoticData
                    }
                );
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected verify() to throw, but it did not');

            expect(ReactNativeSiliconModule.verify).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [
            fc.oneof(
                fc.constant('ES256'),
                fc.constant('ES384'),
                fc.constant('ES512'),
                fc.constant('RS256'),
                fc.constant('RS384'),
                fc.constant('RS512'),
                fc.constant('PS256'),
                fc.constant('PS384'),
                fc.constant('PS512'),
                fc.constant(undefined),
                fc.anything()
            )
        ],
        { numRuns: 1000 }
    )('should throw when opts.alorithm is not a valid string literal and not undefined (for internal keys)', async (chaoticData) => {
        if (chaoticData === "ES256" || 
            chaoticData === "ES384" || 
            chaoticData === "ES512" || 
            chaoticData === "RS256" || 
            chaoticData === "RS384" || 
            chaoticData === "RS512" || 
            chaoticData === "PS256" || 
            chaoticData === "PS384" || 
            chaoticData === "PS512" || 
            chaoticData === undefined
        ) {
            await expect(
                verify(
                    validPayload, 
                    validSignature, 
                    {
                        alias: 'some-random-alias',
                        algorithm: chaoticData
                    }
                )
            ).resolves.toBe(defaultMockData)
            expect(ReactNativeSiliconModule.verify).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                await verify(
                    validPayload, 
                    validSignature, 
                    {
                        alias: 'some-random-alias',
                        // @ts-expect-error
                        algorithm: chaoticData
                    }
                );
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected verify() to throw, but it did not');

            expect(ReactNativeSiliconModule.verify).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when opts.pubkey is not a string and is not empty (for external keys)', async (chaoticData) => {
        if (typeof chaoticData == 'string' && chaoticData.trim().length > 0) {
            await expect(
                verify(
                    validPayload, 
                    validSignature, 
                    {
                        pubkey: chaoticData,
                        algorithm: 'ES256'
                    }
                )
            ).resolves.toBe(defaultMockData)
            expect(ReactNativeSiliconModule.verify).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                await verify(
                    validPayload, 
                    validSignature, 
                    {
                        // @ts-expect-error
                        pubkey: chaoticData,
                        algorithm: 'ES256'
                    }
                );
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected verify() to throw, but it did not');

            expect(ReactNativeSiliconModule.verify).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [
            fc.oneof(
                fc.constant('ES256'),
                fc.constant('ES384'),
                fc.constant('ES512'),
                fc.constant('RS256'),
                fc.constant('RS384'),
                fc.constant('RS512'),
                fc.constant('PS256'),
                fc.constant('PS384'),
                fc.constant('PS512'),
                fc.anything()
            )
        ],
        { numRuns: 1000 }
    )('should throw when opts.alorithm is not a valid string literal (for external keys)', async (chaoticData) => {
        if (chaoticData === "ES256" || 
            chaoticData === "ES384" || 
            chaoticData === "ES512" || 
            chaoticData === "RS256" || 
            chaoticData === "RS384" || 
            chaoticData === "RS512" || 
            chaoticData === "PS256" || 
            chaoticData === "PS384" || 
            chaoticData === "PS512"
        ) {
            await expect(
                verify(
                    validPayload, 
                    validSignature, 
                    {
                        pubkey: 'some-random-pubkey',
                        algorithm: chaoticData
                    }
                )
            ).resolves.toBe(defaultMockData)
            expect(ReactNativeSiliconModule.verify).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                await verify(
                    validPayload, 
                    validSignature, 
                    {
                        pubkey: 'some-random-pubkey',
                        // @ts-expect-error
                        algorithm: chaoticData
                    }
                );
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected verify() to throw, but it did not');

            expect(ReactNativeSiliconModule.verify).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });
});
