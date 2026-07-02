import { vi, describe, it, expect} from 'vitest';
import { test } from '@fast-check/vitest';
import fc from 'fast-check';
import { attestKey, deleteAllKeys, deleteKey, generateKey, getKeyInfo, getPubKey, keyExists, listKeys, validateKey } from '../keys';
import { SiliconError, SiliconErrorCode } from '../../../errors';
import ReactNativeSiliconModule from '../../../module';
import { createBridgeFailure, createBridgeSuccess } from '../../../__test_utils__/factories/bridge-result';

describe('generateKey()', () => {
    const mockVal = createBridgeSuccess(undefined);
    vi.mocked(ReactNativeSiliconModule.generateKey).mockResolvedValue(mockVal);

    const validOpts = {
        purposes: ['SIGN' as const, 'VERIFY' as const],
        userAuth: {
            require: true,
            timeout: 10,
            invalidateOnEnrollment: true,
            policy: 'BIOMETRICS_OR_CREDENTIAL' as const
        },
        attestChallenge: new Uint8Array([10, 20, 30, 40]),
        android: {
            algorithm: 'EC_P256' as const,
            digests: ['SHA256' as const],
            signaturePaddingAlgorithm: 'PSS' as const,
            hardwarePolicy: 'REQUIRE_STRONGBOX' as const
        },
        ios: {
            algorithm: 'RSA_2048' as const,
            digests: ['SHA256' as const, 'SHA512' as const],
            signaturePaddingAlgorithm: 'PKCS1' as const,
            hardwarePolicy: 'SOFTWARE_ONLY' as const
        }
    };

    it('should successfully return void when only an alias is provided', async () => {
        await expect(generateKey('some-random-alias')).resolves.toBeUndefined();
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledOnce();
    });

    it('should successfully return void when an alias and options are provided', async () => {
        await expect(
            generateKey('some-random-alias', validOpts)
        ).resolves.toBeUndefined();
        
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledOnce();
    });

    it('should throw when a failure is returned over the bridge', async () => {
        const mockFailVal = createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, 'test error message', "some-error-stack-trace");
        vi.mocked(ReactNativeSiliconModule.generateKey).mockResolvedValueOnce(mockFailVal);
        
        let didThrow = true;
        try {
            await generateKey('some-random-alias', validOpts);
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) expect.fail('Expected generateKey to throw an error, but it did not.');

        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledOnce();
    });

    it('should throw when no params are provided', async () => {    
        try {
            // @ts-expect-error - Intentionally passing nothing
            await generateKey();
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything()]
    )('should throw when alias is not a string', async (chaoticData) => {
        
        const isValid = typeof chaoticData == 'string' && chaoticData.trim().length > 0;

        if (isValid) {
            await expect(generateKey(chaoticData)).resolves.toBeUndefined();
            expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledOnce();
        } else {
            let didThrow = true;
            try {
                // @ts-expect-error - Intentionally passing incorrect type
                await generateKey(chaoticData);
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) {
                expect.fail('Expected generateKey to throw an error, but it did not.');
            }

            expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    it('should throw when opts is not an object', async () => {    
        try {
            // @ts-expect-error - Intentionally passing incorrect type
            await generateKey('some-random-alias', 10);
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.purposes is not an array', async () => {    
        try {
            // @ts-expect-error - Intentionally passing incorrect type
            await generateKey('some-random-alias', { purposes: 10 });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.purposes an empty array', async () => {    
        try {
            await generateKey('some-random-alias', { purposes: [] });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.purposes contains an invalid string literal', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { purposes: ['INVALID_VALUE'] });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.purposes contains conflicting purposes', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { purposes: ['SIGN', 'ENCRYPT'] });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.userAuth is not an object', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { userAuth: 10 });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.userAuth.require is not boolean', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { userAuth: { require: 10 } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.userAuth.timeout is not a number', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { userAuth: { timeout: 'random-string' } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.userAuth.timeout is < 0', async () => {    
        try {
            await generateKey('some-random-alias', { userAuth: { timeout: -1 } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.userAuth.timeout is > 6000', async () => {    
        try {
            await generateKey('some-random-alias', { userAuth: { timeout: 6001 } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.userAuth.invalidateOnEnrollment is not boolean', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { userAuth: { invalidateOnEnrollment: 10 } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.userAuth.policy is not a string', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { userAuth: { policy: 10 } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.userAuth.policy is an invalid string literal', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { userAuth: { policy: 'BAD_VALUE' } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.attestChallenge is not a Uint8Array', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { attestChallenge: 'random-string' });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android is not an object', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { android: 10 });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android.algorithm is not a string', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { android: { algorithm: 10 } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android.algorithm is not a valid string literal', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { android: { algorithm: 'INVALID' } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android.digests is not an array', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { android: { digests: 'INVALID' } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android.digests is an empty array', async () => {    
        try {
            await generateKey('some-random-alias', { android: { digests: [] } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android.digests contains an invalid string literal', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { android: { digests: ['INVALID'] } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android.signaturePaddingAlgorithm is not a string', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { android: { signaturePaddingAlgorithm: 10 } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android.signaturePaddingAlgorithm contains an invalid string literal', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { android: { signaturePaddingAlgorithm: 'INVALID' } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android.hardwarePolicy is not a string', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { android: { hardwarePolicy: 10 } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android.hardwarePolicy contains an invalid string literal', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { android: { hardwarePolicy: 'INVALID' } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios is not an object', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { ios: 10 });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios.algorithm is not a string', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { ios: { algorithm: 10 } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios.algorithm is not a valid string literal', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { ios: { algorithm: 'INVALID' } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios.digests is not an array', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { ios: { digests: 'INVALID' } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios.digests is an empty array', async () => {    
        try {
            await generateKey('some-random-alias', { ios: { digests: [] } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios.digests contains an invalid string literal', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { ios: { digests: ['INVALID'] } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios.signaturePaddingAlgorithm is not a string', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { ios: { signaturePaddingAlgorithm: 10 } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios.signaturePaddingAlgorithm contains an invalid string literal', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { ios: { signaturePaddingAlgorithm: 'INVALID' } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios.hardwarePolicy is not a string', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { ios: { hardwarePolicy: 10 } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios.hardwarePolicy contains an invalid string literal', async () => {    
        try {
            // @ts-expect-error
            await generateKey('some-random-alias', { ios: { hardwarePolicy: 'INVALID' } });
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });
});

describe('deleteKey()', () => {
    const defaultMockData = true;
    const mockVal = createBridgeSuccess(defaultMockData);
    vi.mocked(ReactNativeSiliconModule.deleteKey).mockResolvedValue(mockVal);

    it('should successfully return a boolean when an alias is provided', async () => {
        await expect(deleteKey('some-random-alias')).resolves.toBe(defaultMockData);
        expect(ReactNativeSiliconModule.deleteKey).toHaveBeenCalledOnce();
    });

    it('should throw when bridge returns failure result', async () => {
        const mockFailVal = createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, 'test error message', "some-error-stack-trace");
        vi.mocked(ReactNativeSiliconModule.deleteKey).mockResolvedValueOnce(mockFailVal);
        
        let didThrow = true;
        try {
            await deleteKey('some-random-alias');
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) expect.fail('Expected deleteKey to throw an error, but it did not.');

        expect(ReactNativeSiliconModule.deleteKey).toHaveBeenCalledOnce();
    });

    it('should throw when an alias is not provided', async () => {
        let didThrow = true;

        try {
            // @ts-expect-error
            await deleteKey();
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) {
            expect.fail('Expected deleteKey to throw an error, but it did not.');
        }

        expect(ReactNativeSiliconModule.deleteKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything()]
    )('should throw when an alias is not a string', async (chaoticData) => {

        const isValid = typeof chaoticData == 'string' && chaoticData.trim().length > 0;

        if (isValid) {
            await expect(deleteKey(chaoticData)).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.deleteKey).toHaveBeenCalledOnce();
        } else {
            let didThrow = true;

            try {
                // @ts-expect-error
                await deleteKey(chaoticData);
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) {
                expect.fail('Expected deleteKey to throw an error, but it did not.');
            }

            expect(ReactNativeSiliconModule.deleteKey).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    })
});

describe('deleteAllKeys()', () => {
    const defaultMockData = 10;
    const mockVal = createBridgeSuccess(defaultMockData);
    vi.mocked(ReactNativeSiliconModule.deleteAllKeys).mockResolvedValue(mockVal);

    it('should successfully return a number when no prefix is provided', async () => {
        await expect(deleteAllKeys()).resolves.toBe(defaultMockData);
        expect(ReactNativeSiliconModule.deleteAllKeys).toHaveBeenCalledOnce();
    });

    it('should successfully return a number when a prefix is provided', async () => {
        await expect(deleteAllKeys('some-random-prefix')).resolves.toBe(defaultMockData);
        expect(ReactNativeSiliconModule.deleteAllKeys).toHaveBeenCalledOnce();
    });

    it('should throw when bridge returns failure result', async () => {
        const mockFailVal = createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, 'test error message', "some-error-stack-trace");
        vi.mocked(ReactNativeSiliconModule.deleteAllKeys).mockResolvedValueOnce(mockFailVal);
        
        let didThrow = true;
        try {
            await deleteAllKeys();
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) {
            expect.fail('Expected deleteAllKeys to throw an error, but it did not.');
        }

        expect(ReactNativeSiliconModule.deleteAllKeys).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()]
    )('should throw when prefix is not a string or is an empty string', async (chaoticData) => {
        // Must be a non-empty string, or undefined to be valid
        const isValid = (typeof chaoticData === 'string' && chaoticData.trim().length > 0) || chaoticData === undefined;

        if (isValid) {
            await expect(deleteAllKeys(chaoticData)).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.deleteAllKeys).toHaveBeenCalledOnce();
        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await deleteAllKeys(chaoticData);
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) {
                expect.fail('Expected deleteAllKeys to throw an error, but it did not.');
            }

            expect(ReactNativeSiliconModule.deleteAllKeys).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });
});

describe('keyExists()', () => {
    const mockVal = createBridgeSuccess(true);
    vi.mocked(ReactNativeSiliconModule.keyExists).mockResolvedValue(mockVal);

    it('should successfully return a boolean when an alias is provided', async () => {
        await expect(keyExists('some-random-alias')).resolves.toBe(true);
        expect(ReactNativeSiliconModule.keyExists).toHaveBeenCalledOnce();
    });

    it('should throw when bridge returns failure result', async () => {
        const mockFailVal = createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, 'test error message', "some-error-stack-trace");
        vi.mocked(ReactNativeSiliconModule.keyExists).mockResolvedValueOnce(mockFailVal);
        
        let didThrow = true;
        try {
            await keyExists('some-random-alias');
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) {
            expect.fail('Expected keyExists to throw an error, but it did not.');
        }

        expect(ReactNativeSiliconModule.keyExists).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()]
    )('should throw when alias is not a string or is an empty string', async (chaoticData) => {
        const isValid = typeof chaoticData == 'string' && chaoticData.trim().length > 0;

        if (isValid) {
            await expect(keyExists(chaoticData)).resolves.toBe(true);
            expect(ReactNativeSiliconModule.keyExists).toHaveBeenCalledOnce();
        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await keyExists(chaoticData);
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) {
                expect.fail('expected keyExists to throw, but it did not');
            }

            expect(ReactNativeSiliconModule.keyExists).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });
});

describe('listKeys()', () => {
    const defaultMockData = ['alias1', 'alias2', 'alias3']
    const mockVal = createBridgeSuccess(defaultMockData);
    vi.mocked(ReactNativeSiliconModule.listKeys).mockResolvedValue(mockVal);

    it('should successfully return a string array when prefix is not provided', async () => {
        await expect(listKeys()).resolves.toBe(defaultMockData);
        expect(ReactNativeSiliconModule.listKeys).toHaveBeenCalledOnce();
    });

    it('should successfully return a string array when prefix is provided', async () => {
        await expect(listKeys('some-random-prefix')).resolves.toBe(defaultMockData);
        expect(ReactNativeSiliconModule.listKeys).toHaveBeenCalledOnce();
    });

    it('should throw when bridge returns failure result', async () => {
        const mockFailVal = createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, 'test error message', "some-error-stack-trace");
        vi.mocked(ReactNativeSiliconModule.listKeys).mockResolvedValueOnce(mockFailVal);
        
        let didThrow = true;
        try {
            await listKeys();
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) {
            expect.fail('Expected listKeys to throw an error, but it did not.');
        }

        expect(ReactNativeSiliconModule.listKeys).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()]
    )('should throw when prefix is not a string and not undefined', async (chaoticData) => {
        const isValid = typeof chaoticData == 'string' || chaoticData === undefined;

        if (isValid) {
            await expect(listKeys(chaoticData)).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.listKeys).toHaveBeenCalledOnce();
        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await listKeys(chaoticData);
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) {
                expect.fail('expected listKeys to throw, but it did not');
            }

            expect(ReactNativeSiliconModule.listKeys).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });
});

describe('validateKey()', () => {
    const defaultMockData = 'VALID' as const;
    const mockVal = createBridgeSuccess(defaultMockData);
    vi.mocked(ReactNativeSiliconModule.validateKey).mockResolvedValue(mockVal);

    const validStatusArr = ['VALID' as const, 'MISSING' as const, 'INVALIDATED' as const, 'UNRECOVERABLE' as const]

    it.each(validStatusArr)('should successfully return a valid string literal when an alias is provided', async (expectedStatus) => {
        const currentMockData = createBridgeSuccess(expectedStatus);
        vi.mocked(ReactNativeSiliconModule.validateKey).mockResolvedValueOnce(currentMockData);

        await expect(validateKey('some-random-alias')).resolves.toBe(expectedStatus);
        expect(ReactNativeSiliconModule.validateKey).toHaveBeenCalledOnce();
    });

    it('should throw when bridge returns failure result', async () => {
        const mockFailVal = createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, 'test error message', "some-error-stack-trace");
        vi.mocked(ReactNativeSiliconModule.validateKey).mockResolvedValueOnce(mockFailVal);
        
        let didThrow = true;
        try {
            await validateKey('some-random-alias');
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) {
            expect.fail('Expected validateKey to throw an error, but it did not.');
        }

        expect(ReactNativeSiliconModule.validateKey).toHaveBeenCalledOnce();
    });

    it('should throw when an alias is not provided', async () => {
        let didThrow = true;
        try {
            // @ts-expect-error
            await validateKey();
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) {
            expect.fail('expected validateKey to throw, but it did not');
        }

        expect(ReactNativeSiliconModule.validateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything()]
    )('should throw when alias is not a string or is an empty string', async (chaoticData) => {
        const isValid = typeof chaoticData == 'string' && chaoticData.trim().length > 0;

        if (isValid) {
            await expect(validateKey(chaoticData)).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.validateKey).toHaveBeenCalledOnce();
        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await validateKey(chaoticData);
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) {
                expect.fail('expected validateKey to throw, but it did not');
            }

            expect(ReactNativeSiliconModule.validateKey).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });
});

describe('getPubKey()', () => {
    const defaultMockData = new Uint8Array([10, 20, 30]);
    const mockVal = createBridgeSuccess(defaultMockData);
    vi.mocked(ReactNativeSiliconModule.getPubKey).mockResolvedValue(mockVal);

    test.prop(
        [fc.anything()]
    )('should throw when alias is not a string or is an empty string', async (chaoticData) => {
        const isValid = typeof chaoticData == 'string' && chaoticData.trim().length > 0;

        if (isValid) {
            await expect(getPubKey(chaoticData, 'SPKI')).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();
        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await getPubKey(chaoticData, 'SPKI');
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) {
                expect.fail('expected getPubKey to throw, but it did not');
            }

            expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything()]
    )('should throw when format is not a valid string literal', async (chaoticData) => {
        const isValid = chaoticData === 'PEM' || chaoticData === 'B64' || chaoticData === 'B64URL' || chaoticData === 'SPKI';

        if (isValid) {
            await expect(getPubKey('some-random-alias', chaoticData)).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();
        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await getPubKey('some-random-alias', chaoticData);
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) {
                expect.fail('expected getPubKey to throw, but it did not');
            }

            expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    const strFormatsArr = ['PEM' as const, 'B64' as const, 'B64URL' as const];
    
    it.each(strFormatsArr)("should successfully return a string for '%s' format", async (format) => {
        const mockData = "some-random-public-key";
        const mockVal = createBridgeSuccess(mockData);
        vi.mocked(ReactNativeSiliconModule.getPubKey).mockResolvedValueOnce(mockVal);

        await expect(getPubKey('some-random-alias', format)).resolves.toBe(mockData);
        expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();
    });

    it.each(strFormatsArr)("should throw if bridge returns a Uint8Array for '%s' format", async (format) => {
        let didThrow = true;
        try {
            await getPubKey('some-random-alias', format);
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) {
            expect.fail('expected getPubKey to throw, but it did not');
        }

        expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();
    });

    it("should successfully return a Uint8Array for 'SPKI' format", async () => {
        await expect(getPubKey('some-random-alias', "SPKI")).resolves.toBe(defaultMockData);
        expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();
    });

    it("should successfully return a Uint8Array for 'SPKI' format when the bridge returns a standard array", async () => {
        const mockData = [10, 20, 30];
        const mockVal = createBridgeSuccess(mockData);
        // @ts-expect-error - Purposely returning a standard array
        vi.mocked(ReactNativeSiliconModule.getPubKey).mockResolvedValueOnce(mockVal);
        
        await expect(getPubKey('some-random-alias', "SPKI")).resolves.toStrictEqual(new Uint8Array(mockData));
        expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();
    });

    it("should successfully return a Uint8Array for 'SPKI' format when the bridge returns ArrayBuffer", async () => {
        // Allocate the ArrayBuffer and write data into it using a View
        const mockData = new ArrayBuffer(3);
        const bufferView = new Uint8Array(mockData);
        bufferView[0] = 10;
        bufferView[1] = 20;
        bufferView[2] = 30;

        const mockVal = createBridgeSuccess(mockData);
        // @ts-expect-error - Purposely returning an ArrayBuffer
        vi.mocked(ReactNativeSiliconModule.getPubKey).mockResolvedValueOnce(mockVal);
        
        await expect(getPubKey('some-random-alias', "SPKI")).resolves.toStrictEqual(new Uint8Array([10, 20, 30]));
        expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();
    });

    it("should throw if bridge returns a string for 'SPKI' format", async () => {
        const mockData = "some-random-public-key";
        const mockVal = createBridgeSuccess(mockData);
        vi.mocked(ReactNativeSiliconModule.getPubKey).mockResolvedValueOnce(mockVal);
        
        let didThrow = true;
        try {
            await getPubKey('some-random-alias', 'SPKI');
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) {
            expect.fail('expected getPubKey to throw, but it did not');
        }

        expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();
    });

    it('should throw when bridge returns failure result', async () => {
        const mockFailVal = createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, 'test error message', "some-error-stack-trace");
        vi.mocked(ReactNativeSiliconModule.getPubKey).mockResolvedValueOnce(mockFailVal);
        
        let didThrow = true;
        try {
            await getPubKey('some-random-alias', 'SPKI');
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) {
            expect.fail('Expected getPubKey to throw an error, but it did not.');
        }

        expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();
    });
});

describe('attestKey()', () => {
    const mockIosAttestKeyOnce = (isPubKeyStr: boolean) => {
        const mockData = {
            platform: 'IOS' as const,
            signingPubKey: isPubKeyStr ? 'some-random-pubkey' : new Uint8Array([10, 20, 30]),
            attestationObject: 'some-random-attestation-object'
        };
        const mockVal = createBridgeSuccess(mockData);
        vi.mocked(ReactNativeSiliconModule.attestKey).mockResolvedValueOnce(mockVal);

        return mockData;
    }

    const mockAndroidAttestKeyOnce = () => {
        const mockData = {
            platform: 'ANDROID' as const,
            certChain: ['some-random-cert-1', 'some-random-cert-2', 'some-random-cert-3']
        };
        const mockVal = createBridgeSuccess(mockData);
        vi.mocked(ReactNativeSiliconModule.attestKey).mockResolvedValue(mockVal);

        return mockData;
    }

    it('should throw when bridge returns failure result', async () => {
        const mockFailVal = createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, 'test error message', "some-error-stack-trace");
        vi.mocked(ReactNativeSiliconModule.attestKey).mockResolvedValueOnce(mockFailVal);
        
        let didThrow = true;
        try {
            await attestKey('some-random-alias', 'SPKI');
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) {
            expect.fail('Expected attestKey to throw an error, but it did not.');
        }

        expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()]
    )('should throw if alias is not a string or is an empty string', async (chaoticData) => {
        const mockData = mockAndroidAttestKeyOnce();

        const isValid = typeof chaoticData == 'string' && chaoticData.trim().length > 0;

        if (isValid) {
            await expect(attestKey(chaoticData, 'SPKI')).resolves.toBe(mockData);
            expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await attestKey(chaoticData, "SPKI");
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) {
                expect.fail('expected attestKey to throw, but it did not');
            }

            expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything()]
    )('should throw if pubKeyFormat is not a valid string literal', async (chaoticData) => {
        const mockData = mockAndroidAttestKeyOnce();

        const isValid = chaoticData === "SPKI" || chaoticData === "PEM" || chaoticData === "B64" || chaoticData === "B64URL";

        if (isValid) {
            await expect(attestKey('some-random-alias', chaoticData)).resolves.toBe(mockData);
            expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await attestKey('some-random-alias', chaoticData);
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) {
                expect.fail('expected attestKey to throw, but it did not');
            }

            expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    it('should return a valid AttestResult for android', async () => {
        const mockData = mockAndroidAttestKeyOnce();

        await expect(attestKey('some-random-alias', "SPKI")).resolves.toStrictEqual(mockData);
        expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();
    });

    const iosPubKeyStrFormats = ['PEM' as const, 'B64' as const, 'B64URL' as const];
    it.each(iosPubKeyStrFormats)("should return a valid AttestResult for ios format is '%s'", async (format) => {
        // Mock a string for the pubkey
        const mockData = mockIosAttestKeyOnce(true);

        await expect(attestKey('some-random-alias', format)).resolves.toStrictEqual(mockData);
        expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();
    });

    it.each(iosPubKeyStrFormats)("should throw for ios when format is '%s' and bridge returns a pub key Uint8Array", async (format) => {
        // Mock a Uint8Array for the pubkey
        mockIosAttestKeyOnce(false);
        
        let didThrow = true;
        try {
            await attestKey('some-random-alias', format);
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) {
            expect.fail('expected attestKey to throw, but it did not');
        }

        expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();
    });

    it("should return a valid AttestResult for ios when format is 'SPKI'", async () => {
        const mockData = mockIosAttestKeyOnce(false);

        await expect(attestKey('some-random-alias', 'SPKI')).resolves.toStrictEqual(mockData);
        expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();
    });

    it("should throw for ios when format is 'SPKI' and bridge returns a pub key string", async () => {
        // Mock a string for the pubkey
        mockIosAttestKeyOnce(true);
        
        let didThrow = true;
        try {
            await attestKey('some-random-alias', 'SPKI');
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) {
            expect.fail('expected attestKey to throw, but it did not');
        }

        expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();
    });
});

describe('getKeyInfo()', () => {
    const defaultMockData = {
        alias: 'some-random-alias',
        algorithm: 'EC_256',
        curve: 'P-256',
        keySize: 256,
        digests: ['SHA256' as const],
        securityLevel: "STRONGBOX" as const,
        purposes: ["SIGN" as const, "VERIFY" as const],
        isUserAuthRequired: true,
        isInvalidatedByBiometricEnrollment: true,
        userAuthValidityDurationSecs: 10,
    };
    const mockVal = createBridgeSuccess(defaultMockData);
    vi.mocked(ReactNativeSiliconModule.getKeyInfo).mockResolvedValue(mockVal);

    it('should successfully return a KeyInfo object', async () => {
        await expect(getKeyInfo('some-random-alias')).resolves.toBe(defaultMockData);
        expect(ReactNativeSiliconModule.getKeyInfo).toHaveBeenCalledOnce();
    });

    it('should throw when bridge returns failure result', async () => {
        const mockFailVal = createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, 'test error message', "some-error-stack-trace");
        vi.mocked(ReactNativeSiliconModule.getKeyInfo).mockResolvedValueOnce(mockFailVal);
        
        let didThrow = true;
        try {
            await getKeyInfo('some-random-alias');
            didThrow = false;
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }

        if (!didThrow) {
            expect.fail('Expected getKeyInfo to throw an error, but it did not.');
        }

        expect(ReactNativeSiliconModule.getKeyInfo).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()]
    )('should throw when alias is not a string, or is empty', async (chaoticData) => {
        const isValid = typeof chaoticData == 'string' && chaoticData.trim().length > 0;

        if (isValid) {
            await expect(getKeyInfo(chaoticData)).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.getKeyInfo).toHaveBeenCalledOnce();
        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await getKeyInfo(chaoticData);
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) {
                expect.fail('expected getKeyInfo to throw, but it did not');
            }

            expect(ReactNativeSiliconModule.getKeyInfo).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });
});
