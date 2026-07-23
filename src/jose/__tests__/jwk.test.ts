import { describe, it, expect, vi, onTestFailed } from "vitest";
import { test } from '@fast-check/vitest';
import fc from 'fast-check';
import { getJwk } from '../jwk';
import ReactNativeSiliconModule from "../../module";
import { createBridgeFailure, createBridgeSuccess } from "../../__test_utils__/factories/bridge-result";
import { SiliconError, SiliconErrorCode } from "../../errors";

describe('getJwk()', () => {
    const mockSuccess = () => {
        const mockData = {
            key1: 'random-data',
            key2: 'random-data'
        }
        const mockVal = createBridgeSuccess(mockData);
        vi.mocked(ReactNativeSiliconModule.getJwk).mockResolvedValue(mockVal);
        return mockData;
    };

    const mockFailure = () => {
        const mockErr = createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, 'some random error message', 'some-random-native-stack');
        vi.mocked(ReactNativeSiliconModule.getJwk).mockResolvedValue(mockErr);
    };
    
    it('should return successfully when valid params are provided', async () => {
        const mockVal = mockSuccess();
        await expect(getJwk('some-random-alias', 'SHA256')).resolves.toStrictEqual(mockVal);
        expect(ReactNativeSiliconModule.getJwk).toHaveBeenCalledOnce();
    });

    it('should throw when bridge returns a failure result', async () => {
        mockFailure();
        await expect(getJwk('some-random-alias', 'SHA256')).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.getJwk).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when alias is not a string, or is an empty string', async (chaoticData) => {
        const mockVal = mockSuccess();

        if (typeof chaoticData == 'string' && chaoticData.trim().length > 0) {
            await expect(getJwk(chaoticData, 'SHA256')).resolves.toStrictEqual(mockVal);
            expect(ReactNativeSiliconModule.getJwk).toHaveBeenCalledOnce();
        } else {
            // @ts-expect-error
            await expect(getJwk(chaoticData, 'SHA256')).rejects.instanceOf(SiliconError);
            expect(ReactNativeSiliconModule.getJwk).toHaveBeenCalledTimes(0);
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
    )('should throw when digest is defined but not a valid string literal', async (chaoticData) => {
        const mockVal = mockSuccess();

        if (chaoticData === 'SHA256' ||
            chaoticData === 'SHA384' ||
            chaoticData === 'SHA512' ||
            chaoticData === undefined
        ) {
            await expect(getJwk('some-random-alias', chaoticData)).resolves.toStrictEqual(mockVal);
            expect(ReactNativeSiliconModule.getJwk).toHaveBeenCalledOnce();
        } else {
            // @ts-expect-error
            await expect(getJwk('some-random-alias', chaoticData)).rejects.instanceOf(SiliconError);
            expect(ReactNativeSiliconModule.getJwk).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });
});
