import { vi, describe, it, expect} from 'vitest';
import { generateKey } from '../keys';
import { SiliconError } from '../../../errors';
import ReactNativeSiliconModule from '../../../module';
import { createBridgeSuccess } from '../../../__test_utils__/factories/bridge-result';

describe('generateKey()', () => {
    const mockVal = createBridgeSuccess(undefined);
    vi.mocked(ReactNativeSiliconModule.generateKey).mockResolvedValue(mockVal);

    it('should successfully return void when only an alias is provided', async () => {
        await expect(generateKey('some-random-alias')).resolves.toBeUndefined();
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledOnce();
    });

    it('should successfully return void when an alias and options are provided', async () => {
        await expect(
            generateKey(
                'some-random-alias',
                {
                    purposes: ['SIGN', 'VERIFY'],
                    userAuth: {
                        require: true,
                        timeout: 10,
                        invalidateOnEnrollment: true,
                        policy: 'BIOMETRICS_OR_CREDENTIAL'
                    },
                    attestChallenge: new Uint8Array([10, 20, 30, 40]),
                    android: {
                        algorithm: 'EC_P256',
                        digests: ['SHA256'],
                        signaturePaddingAlgorithm: 'PSS',
                        hardwarePolicy: 'REQUIRE_STRONGBOX'
                    },
                    ios: {
                        algorithm: 'RSA_2048',
                        digests: ['SHA256', 'SHA512'],
                        signaturePaddingAlgorithm: 'PKCS1',
                        hardwarePolicy: 'SOFTWARE_ONLY'
                    }
                }
            )
        ).resolves.toBeUndefined();
        
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

    it('should throw when alias is not a string', async () => {    
        try {
            // @ts-expect-error - Intentionally passing incorrect type
            await generateKey(10);
            expect.fail('Expected generateKey to throw an error, but it did not.');
        } catch (error) {
            expect(error).toBeInstanceOf(SiliconError);
        }
        expect(ReactNativeSiliconModule.generateKey).toHaveBeenCalledTimes(0);
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
            console.log(`error is ${error}`)
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
