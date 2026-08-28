import { vi, describe, it, expect} from 'vitest';
import { test } from '@fast-check/vitest';
import fc from 'fast-check';
import { attestKey, deleteAllKeys, deleteKey, generateKey, getKeyInfo, getPubKey, keyExists, listKeys, validateKey } from '../keys';
import { SiliconError, SiliconErrorCode } from '../../../errors';
import ReactNativeSiliconModule from '../../../module';
import { createBridgeFailure, createBridgeSuccess } from '../../../__test_utils__/factories/bridge-result';
import { fcCustomArbitraries } from '../../../__test_utils__/fast-check/arbitraries';
import { isSafeNumber } from '../../../utils/validation';
import { cartesianProduct } from '../../../__test_utils__/utils/cartesian-product';

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

        await expect(generateKey('some-random-alias', validOpts)).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledOnce();
    });

    it('should throw when no params are provided', async () => {    
        // @ts-expect-error - Intentionally passing nothing
        await expect(generateKey()).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when alias is not a string', async (chaoticData) => {
        if (typeof chaoticData == 'string' && chaoticData.trim().length > 0) {
            await expect(generateKey(chaoticData)).resolves.toBeUndefined();
            expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledOnce();

        } else {
            // @ts-expect-error - Intentionally passing incorrect type
            await expect(generateKey(chaoticData)).rejects.instanceOf(SiliconError);
            expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [
            fcCustomArbitraries.anything.nonPlainObj().filter((v) => v !== undefined)
        ],
        { numRuns: 1000 }
    )('should throw when opts is not an object', async (chaoticData) => {    
        // @ts-expect-error - Intentionally passing incorrect type
        await expect(generateKey('some-random-alias', chaoticData)).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });
    
    test.prop(
        [
            fcCustomArbitraries.anything.nonArray().filter((v) => v !== undefined)
        ],
        { numRuns: 1000 }
    )('should throw when opts.purposes is not an array', async (chaoticData) => {    
        // @ts-expect-error - Intentionally passing incorrect type
        await expect(generateKey('some-random-alias', { purposes: chaoticData })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.purposes is an empty array', async () => {    
        await expect(generateKey('some-random-alias', { purposes: [] })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.purposes contains an invalid string literal', async () => {    
        // @ts-expect-error - Passing invalid string literal
        await expect(generateKey('some-random-alias', { purposes: ['INVALID_VALUE'] })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.purposes contains conflicting purposes', async () => {    
        // @ts-expect-error - Conflicting purposes
        await expect(generateKey('some-random-alias', { purposes: ['SIGN', 'ENCRYPT'] })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [
            fcCustomArbitraries.anything.nonPlainObj().filter((v) => v !== undefined)
        ],
        { numRuns: 1000 }
    )('should throw when opts.userAuth is not an object', async (chaoticData) => {    
        // @ts-expect-error - Intentionally passing incorrect type
        await expect(generateKey('some-random-alias', { userAuth: chaoticData })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [
            fc.anything().filter((v) => typeof v !== 'boolean' && v !== undefined)
        ],
        { numRuns: 1000 }
    )('should throw when opts.userAuth.require is not boolean', async (chaoticData) => {    
        // @ts-expect-error - Intentionally passing incorrect type
        await expect(generateKey('some-random-alias', { userAuth: { require: chaoticData } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [
            fc.anything().filter((v) => !isSafeNumber(v) && v !== undefined)
        ],
        { numRuns: 1000 }
    )('should throw when opts.userAuth.timeout is not type number', async (chaoticData) => {    
        // @ts-expect-error - Intentionally passing incorrect type
        await expect(generateKey('some-random-alias', { userAuth: { timeout: chaoticData } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fcCustomArbitraries.number.negative()],
        { numRuns: 1000 }
    )('should throw when opts.userAuth.timeout is < 0', async (negativeNumber) => {    
        await expect(generateKey('some-random-alias', { userAuth: { timeout: negativeNumber } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fcCustomArbitraries.number.positive().filter((v) => v > 6000)],
        { numRuns: 1000 }
    )('should throw when opts.userAuth.timeout is > 6000', async (numberGt6000) => {    
        await expect(generateKey('some-random-alias', { userAuth: { timeout: numberGt6000 } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything().filter((v) => typeof v !== 'boolean' && v !== undefined)],
        { numRuns: 1000 }
    )('should throw when opts.userAuth.invalidateOnEnrollment is not boolean', async (chaoticData) => {    
        // @ts-expect-error - Intentionally passing wrong type
        await expect(generateKey('some-random-alias', { userAuth: { invalidateOnEnrollment: chaoticData } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything().filter((v) => typeof v !== 'string' && v !== undefined)],
        { numRuns: 1000 }
    )('should throw when opts.userAuth.policy is not a string', async (chaoticData) => {    
        // @ts-expect-error - Intentionally passing wrong type
        await expect(generateKey('some-random-alias', { userAuth: { policy: chaoticData } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.userAuth.policy is an invalid string literal', async () => {    
        // @ts-expect-error - Intentionally passing invalid string literal
        await expect(generateKey('some-random-alias', { userAuth: { policy: 'BAD_VALUE' } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything().filter((v) => !(v instanceof Uint8Array) && v !== undefined)],
        { numRuns: 1000 }
    )('should throw when opts.attestChallenge is not a Uint8Array', async (chaoticData) => {    
        // @ts-expect-error - Intentionally passing wrong type
        await expect(generateKey('some-random-alias', { attestChallenge: chaoticData })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fcCustomArbitraries.anything.nonPlainObj().filter((v) => v !== undefined)],
        { numRuns: 1000 }
    )('should throw when opts.android is not an object', async (chaoticData) => {    
        // @ts-expect-error - Intentionally passing wrong type
        await expect(generateKey('some-random-alias', { android: chaoticData })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything().filter((v) => typeof v !== 'string' && v !== undefined)],
        { numRuns: 1000 }
    )('should throw when opts.android.algorithm is not a string', async (chaoticData) => {
        // @ts-expect-error - Intentionally passing wrong type
        await expect(generateKey('some-random-alias', { android: { algorithm: chaoticData } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android.algorithm is not a valid string literal', async () => {    
        // @ts-expect-error - Intentionally passing invalid string literal
        await expect(generateKey('some-random-alias', { android: { algorithm: 'INVALID' } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [
            fcCustomArbitraries.anything.nonArray().filter((v) => v !== undefined)
        ],
        { numRuns: 1000 }
    )('should throw when opts.android.digests is not an array', async (chaoticData) => {    
        // @ts-expect-error - Intentionally passing wrong type
        await expect(generateKey('some-random-alias', { android: { digests: chaoticData } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android.digests is an empty array', async () => {    
        await expect(generateKey('some-random-alias', { android: { digests: [] } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android.digests contains an invalid string literal', async () => {    
        // @ts-expect-error - Intentionally passing invalid string literal
        await expect(generateKey('some-random-alias', { android: { digests: ['INVALID'] } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything().filter((v) => typeof v !== 'string' && v !== undefined)],
        { numRuns: 1000 }
    )('should throw when opts.android.signaturePaddingAlgorithm is not a string', async (chaoticData) => {    
        // @ts-expect-error - Intentionally passing wrong type
        await expect(generateKey('some-random-alias', { android: { signaturePaddingAlgorithm: chaoticData } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android.signaturePaddingAlgorithm contains an invalid string literal', async () => {    
        // @ts-expect-error - Intentionally passing invalid string literal
        await expect(generateKey('some-random-alias', { android: { signaturePaddingAlgorithm: 'INVALID' } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything().filter((v) => typeof v !== 'string' && v !== undefined)],
        { numRuns: 1000 }
    )('should throw when opts.android.hardwarePolicy is not a string', async (chaoticData) => {    
        // @ts-expect-error - Intentionally passing wrong type
        await expect(generateKey('some-random-alias', { android: { hardwarePolicy: chaoticData } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.android.hardwarePolicy contains an invalid string literal', async () => {    
        // @ts-expect-error - Intentionally passing invalid string literal
        await expect(generateKey('some-random-alias', { android: { hardwarePolicy: 'INVALID' } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fcCustomArbitraries.anything.nonPlainObj().filter((v) => v !== undefined)],
        { numRuns: 1000 }
    )('should throw when opts.ios is not an object', async (chaoticData) => {
        // @ts-expect-error - Intentionally passing wrong type
        await expect(generateKey('some-random-alias', { ios: chaoticData })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything().filter((v) => typeof v !== 'string' && v !== undefined)],
        { numRuns: 1000 }
    )('should throw when opts.ios.algorithm is not a string', async (chaoticData) => {    
        // @ts-expect-error - Intentionally passing wrong type
        await expect(generateKey('some-random-alias', { ios: { algorithm: chaoticData } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios.algorithm is not a valid string literal', async () => {    
        // @ts-expect-error - Intentionally passing invalid string literal
        await expect(generateKey('some-random-alias', { ios: { algorithm: 'INVALID' } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fcCustomArbitraries.anything.nonArray().filter((v) => v !== undefined)],
        { numRuns: 1000 }
    )('should throw when opts.ios.digests is not an array', async (chaoticData) => {    
        // @ts-expect-error - intentionally passing wrong type
        await expect(generateKey('some-random-alias', { ios: { digests: chaoticData } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios.digests is an empty array', async () => {    
        await expect(generateKey('some-random-alias', { ios: { digests: [] } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios.digests contains an invalid string literal', async () => {    
        // @ts-expect-error - Intentionally passing invalid string literal
        await expect(generateKey('some-random-alias', { ios: { digests: ['INVALID'] } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything().filter((v) => typeof v !== 'string' && v !== undefined)],
        { numRuns: 1000 }
    )('should throw when opts.ios.signaturePaddingAlgorithm is not a string', async (chaoticData) => {    
        // @ts-expect-error - Intentionally passing wrong type
        await expect(generateKey('some-random-alias', { ios: { signaturePaddingAlgorithm: chaoticData } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios.signaturePaddingAlgorithm contains an invalid string literal', async () => {    
        // @ts-expect-error - Intentionally passing invalid string literal
        await expect(generateKey('some-random-alias', { ios: { signaturePaddingAlgorithm: 'INVALID' } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything().filter((v) => typeof v !== 'string' && v !== undefined)],
        { numRuns: 1000 }
    )('should throw when opts.ios.hardwarePolicy is not a string', async (chaoticData) => {
        // @ts-expect-error - Intentionally passing wrong type
        await expect(generateKey('some-random-alias', { ios: { hardwarePolicy: chaoticData } })).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
    });

    it('should throw when opts.ios.hardwarePolicy contains an invalid string literal', async () => {    
        // @ts-expect-error - intentionally pass invalid string literal
        await expect(generateKey('some-random-alias', { ios: { hardwarePolicy: 'INVALID' } })).rejects.instanceOf(SiliconError);
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
        
        await expect(deleteKey('some-random-alias')).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.deleteKey).toHaveBeenCalledOnce();
    });

    it('should throw when an alias is not provided', async () => {
        // @ts-expect-error - no alias provided
        await expect(deleteKey()).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.deleteKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when an alias is not a string', async (chaoticData) => {
        if (typeof chaoticData == 'string' && chaoticData.trim().length > 0) {
            await expect(deleteKey(chaoticData)).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.deleteKey).toHaveBeenCalledOnce();
        } else {
            // @ts-expect-error - intentionally passed incorrect type
            await expect(deleteKey(chaoticData)).rejects.instanceOf(SiliconError);
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
        
        await expect(deleteAllKeys()).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.deleteAllKeys).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when prefix is not a string or is an empty string', async (chaoticData) => {
        if ((typeof chaoticData === 'string' && chaoticData.trim().length > 0) || chaoticData === undefined) {
            await expect(deleteAllKeys(chaoticData)).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.deleteAllKeys).toHaveBeenCalledOnce();
        } else {
            // @ts-expect-error - intentionally passed incorrect type
            await expect(deleteAllKeys(chaoticData)).rejects.instanceOf(SiliconError);
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
        
        await expect(keyExists('some-random-alias')).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.keyExists).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when alias is not a string or is an empty string', async (chaoticData) => {
        if (typeof chaoticData == 'string' && chaoticData.trim().length > 0) {
            await expect(keyExists(chaoticData)).resolves.toBe(true);
            expect(ReactNativeSiliconModule.keyExists).toHaveBeenCalledOnce();
        } else {
            // @ts-expect-error - intentionally passed incorrect type
            await expect(keyExists(chaoticData)).rejects.instanceOf(SiliconError);
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
        
        await expect(listKeys()).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.listKeys).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when prefix is not a string and not undefined', async (chaoticData) => {
        if (typeof chaoticData == 'string' || chaoticData === undefined) {
            await expect(listKeys(chaoticData)).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.listKeys).toHaveBeenCalledOnce();
        } else {
            // @ts-expect-error - intentionally passed incorrect type
            await expect(listKeys(chaoticData)).rejects.instanceOf(SiliconError);
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
        
        await expect(validateKey('some-random-alias')).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.validateKey).toHaveBeenCalledOnce();
    });

    it('should throw when an alias is not provided', async () => {
        // @ts-expect-error - alias not provided
        await expect(validateKey()).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.validateKey).toHaveBeenCalledTimes(0);
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when alias is not a string or is an empty string', async (chaoticData) => {
        const isValid = typeof chaoticData == 'string' && chaoticData.trim().length > 0;

        if (isValid) {
            await expect(validateKey(chaoticData)).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.validateKey).toHaveBeenCalledOnce();
        } else {
            // @ts-expect-error - intentionally passed incorrect type
            await expect(validateKey(chaoticData)).rejects.instanceOf(SiliconError);
            expect(ReactNativeSiliconModule.validateKey).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });
});

describe('getPubKey()', () => {
    const mockUint8Array = () => {
        const mockData = new Uint8Array([10, 20, 30]);
        const mockVal = createBridgeSuccess(mockData);
        vi.mocked(ReactNativeSiliconModule.getPubKey).mockResolvedValue(mockVal);
        return mockData;
    };

    const mockStr = () => {
        const mockData = 'some-random-public-key';
        const mockVal = createBridgeSuccess(mockData);
        vi.mocked(ReactNativeSiliconModule.getPubKey).mockResolvedValue(mockVal);
        return mockData;
    };

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when alias is not a string or is an empty string', async (chaoticData) => {
        const mockData = mockUint8Array();
        
        if (typeof chaoticData == 'string' && chaoticData.trim().length > 0) {
            await expect(getPubKey(chaoticData, 'SPKI')).resolves.toBe(mockData);
            expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();
        } else {
            // @ts-expect-error - intentionally passing invalid value
            await expect(getPubKey(chaoticData, 'SPKI')).rejects.instanceOf(SiliconError);
            expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [
            fc.oneof(
                fc.constant('PEM'),
                fc.constant('B64'),
                fc.constant('B64URL'),
                fc.constant('SPKI'),
                fc.anything()
            )
        ],
        { numRuns: 1000 }
    )('should throw when format is not a valid string literal', async (chaoticData) => {
        if (chaoticData === 'PEM' || chaoticData === 'B64' || chaoticData === 'B64URL' || chaoticData === 'SPKI') {
            let mockData; 
            if (chaoticData === 'SPKI') {
                mockData = mockUint8Array();
            } else {
                mockData = mockStr();
            }

            await expect(getPubKey('some-random-alias', chaoticData)).resolves.toBe(mockData);
            expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();

        } else {
            mockUint8Array();

            // @ts-expect-error - intentionally passed incorrect type
            await expect(getPubKey('some-random-alias', chaoticData)).rejects.instanceOf(SiliconError);
            expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    const strFormatsArr = ['PEM' as const, 'B64' as const, 'B64URL' as const];
    
    it.each(strFormatsArr)("should successfully return a string for '%s' format", async (format) => {
        const mockData = mockStr();

        await expect(getPubKey('some-random-alias', format)).resolves.toBe(mockData);
        expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();
    });

    it.each(strFormatsArr)("should throw if bridge returns a Uint8Array for '%s' format", async (format) => {
        mockUint8Array();
        
        await expect(getPubKey('some-random-alias', format)).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();
    });

    it("should successfully return a Uint8Array for 'SPKI' format", async () => {
        const mockData = mockUint8Array();
        
        await expect(getPubKey('some-random-alias', "SPKI")).resolves.toBe(mockData);
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
        
        await expect(getPubKey('some-random-alias', 'SPKI')).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();
    });

    it('should throw when bridge returns failure result', async () => {
        const mockFailVal = createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, 'test error message', "some-error-stack-trace");
        vi.mocked(ReactNativeSiliconModule.getPubKey).mockResolvedValueOnce(mockFailVal);
        
        await expect(getPubKey('some-random-alias', 'SPKI')).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.getPubKey).toHaveBeenCalledOnce();
    });
});

describe('attestKey()', () => {
    const mockIosAttestKey = (format: 'BYTES' | 'STRING', invertFormat: boolean, pubkeyFormat: 'SPKI' | 'B64' | 'B64URL' | 'PEM', invertPubkeyFormat: boolean) => {
        let mockIsStr;
        switch (format) {
            case 'BYTES': 
                mockIsStr = invertFormat ? true : false;
                break;
            case 'STRING':
                mockIsStr = invertFormat ? false : true;
                break;
        }

        let mockIsPubKeyStr;
        switch (pubkeyFormat) {
            case 'SPKI':
                mockIsPubKeyStr = invertPubkeyFormat ? true : false;
                break;

            case 'B64':
            case 'B64URL':
            case 'PEM':
                mockIsPubKeyStr = invertPubkeyFormat ? false : true;
                break;
        }
        
        const mockData = {
            platform: 'IOS' as const,
            signingPubKey: mockIsPubKeyStr ? 'some-random-pubkey' : new Uint8Array([10, 20, 30]),
            attestationObject: mockIsStr ? 'some-random-attestation-object' : new Uint8Array([10, 20, 30])
        };
        const mockVal = createBridgeSuccess(mockData);
        vi.mocked(ReactNativeSiliconModule.attestKey).mockResolvedValue(mockVal);

        return mockData;
    }

    const mockAndroidAttestKey = (format: 'BYTES' | 'STRING', invertFormat: boolean) => {
        let mockIsStr;
        switch (format) {
            case 'BYTES': 
                mockIsStr = invertFormat ? true : false;
                break;
            case 'STRING':
                mockIsStr = invertFormat ? false : true;
                break;
        }
        
        const mockData = {
            platform: 'ANDROID' as const,
            certChain: mockIsStr ? 
                ['some-random-cert-1', 'some-random-cert-2', 'some-random-cert-3'] : 
                [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]), new Uint8Array([7, 8, 9])]
        };
        const mockVal = createBridgeSuccess(mockData);
        vi.mocked(ReactNativeSiliconModule.attestKey).mockResolvedValue(mockVal);

        return mockData;
    }

    const iosPubKeyStrFormats = ['SPKI', 'PEM', 'B64', 'B64URL'] as const;
    const attestFormats = ['STRING', 'BYTES'] as const;
    const iosCombinations = cartesianProduct(attestFormats, iosPubKeyStrFormats);

    it('should throw when bridge returns failure result', async () => {
        const mockFailVal = createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, 'test error message', "some-error-stack-trace");
        vi.mocked(ReactNativeSiliconModule.attestKey).mockResolvedValueOnce(mockFailVal);
        
        await expect(attestKey('some-random-alias', 'STRING', 'SPKI')).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw if alias is not a string or is an empty string', async (chaoticData) => {
        const mockData = mockAndroidAttestKey('STRING', false);

        if (typeof chaoticData == 'string' && chaoticData.trim().length > 0) {
            await expect(attestKey(chaoticData, 'STRING', 'SPKI')).resolves.toBe(mockData);
            expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();
        } else {
            // @ts-expect-error - intentionally pass incorrect type
            await expect(attestKey(chaoticData,'STRING', "SPKI")).rejects.instanceOf(SiliconError);
            expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw if format is not a valid string literal', async (chaoticData) => {
        if (chaoticData === "BYTES" || chaoticData === "STRING") {
            const mockData = mockAndroidAttestKey('STRING', false);
            await expect(attestKey('some-random-alias', chaoticData, 'SPKI')).resolves.toBe(mockData);
            expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();
        } else {
            mockAndroidAttestKey('STRING', false);
            // @ts-expect-error - Intentionally pass incorrect type
            await expect(attestKey('some-random-alias', chaoticData, 'SPKI')).rejects.instanceOf(SiliconError);
            expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw if pubKeyFormat is not a valid string literal', async (chaoticData) => {        
        // We mock for android here so that the pubKeyFormat doesn't actually affect the returned data
        const mockData = mockAndroidAttestKey('STRING', false);

        if (chaoticData === "SPKI" || chaoticData === "PEM" || chaoticData === "B64" || chaoticData === "B64URL") {
            await expect(attestKey('some-random-alias', 'STRING', chaoticData)).resolves.toBe(mockData);
            expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();

        } else {
            // @ts-expect-error - intentionally pass incorrect type
            await expect(attestKey('some-random-alias', 'STRING', chaoticData)).rejects.instanceOf(SiliconError);
            expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    it.each(attestFormats)("should return a valid AttestResult for android when format is '%s'", async (format) => {
        const mockData = mockAndroidAttestKey(format, false);

        await expect(
            attestKey(
                'some-random-alias', 
                format, 
                "SPKI"
            )
        ).resolves.toStrictEqual(mockData);
        expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();
    });

    it.each(attestFormats)("should throw for android when format is '%s' and bridge returns incorrect type", async (format) => {
        // Invert the format to mock return the incorrect one
        mockAndroidAttestKey(format, true);

        await expect(attestKey('some-random-alias', format, "SPKI")).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();
    });

    it.each(iosCombinations)("should return a valid AttestResult for ios when format format is '%s' pubkeyFormat is '%s'", async (format, pubkeyFormat) => {
        // Mock a string for the pubkey
        const mockData = mockIosAttestKey(format, false, pubkeyFormat, false);

        await expect(attestKey('some-random-alias', format, pubkeyFormat)).resolves.toStrictEqual(mockData);
        expect(ReactNativeSiliconModule.attestKey).toHaveBeenCalledOnce();
    });

    it.each(iosPubKeyStrFormats)("should throw for ios when pubkeyFormat is '%s' and bridge returns a pubkey with the incorrect type", async (pubkeyFormat) => {
        mockIosAttestKey('STRING', false, pubkeyFormat, true);
        
        await expect(attestKey('some-random-alias', 'STRING', pubkeyFormat)).rejects.instanceOf(SiliconError);
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
        
        await expect(getKeyInfo('some-random-alias')).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.getKeyInfo).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when alias is not a string, or is empty', async (chaoticData) => {
        if (typeof chaoticData == 'string' && chaoticData.trim().length > 0) {
            await expect(getKeyInfo(chaoticData)).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.getKeyInfo).toHaveBeenCalledOnce();            
        } else {
            // @ts-expect-error - intentionally pass incorrect type
            await expect(getKeyInfo(chaoticData)).rejects.instanceOf(SiliconError);
            expect(ReactNativeSiliconModule.getKeyInfo).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });
});
