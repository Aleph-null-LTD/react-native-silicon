import { vi, describe, it, expect } from "vitest";
import ReactNativeSiliconModule from '../../../module';
import { createBridgeFailure, createBridgeSuccess } from "../../../__test_utils__/factories/bridge-result";
import { generateSecureRandomBytes } from "../random";
import { SiliconError, SiliconErrorCode } from "../../../errors";
import fc from 'fast-check';
import { test } from '@fast-check/vitest';
import { isSafeNumber } from "../../../utils/validation";

describe('generateSecureRandomBytes()', () => {
    const mockStringResult = () => {
        const defaultMockData = 'some-random-string';
        const defaultMockVal = createBridgeSuccess(defaultMockData);
        vi.mocked(ReactNativeSiliconModule.generateSecureRandomBytes).mockResolvedValue(defaultMockVal);
        
        return defaultMockData;
    };

    const mockUint8ArrayResult = () => {
        const defaultMockData = new Uint8Array([10, 20, 30]);
        const defaultMockVal = createBridgeSuccess(defaultMockData);
        vi.mocked(ReactNativeSiliconModule.generateSecureRandomBytes).mockResolvedValue(defaultMockVal);

        return defaultMockData;
    };

    it("should successfully return a Uint8Array when format is 'BYTES'", async () => {
        const defaultMockData = mockUint8ArrayResult();

        await expect(generateSecureRandomBytes(3, 'BYTES')).resolves.toStrictEqual(defaultMockData);
        expect(ReactNativeSiliconModule.generateSecureRandomBytes).toHaveBeenCalledOnce();
    });

    it("should throw when bridge returns a failure result", async () => {
        const defaultMockVal = createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, 'some random error message', 'some-random-error-stack');
        vi.mocked(ReactNativeSiliconModule.generateSecureRandomBytes).mockResolvedValueOnce(defaultMockVal);

        await expect(generateSecureRandomBytes(3, 'BYTES')).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateSecureRandomBytes).toHaveBeenCalledOnce();
    });

    it("should throw when bridge result contains a string but format is 'BYTES'", async () => {
        mockStringResult();

        await expect(generateSecureRandomBytes(3, 'BYTES')).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateSecureRandomBytes).toHaveBeenCalledOnce();
    });

    it("should successfully return a string when format is 'B64'", async () => {
        const defaultMockData = mockStringResult();

        await expect(generateSecureRandomBytes(3, 'B64')).resolves.toBe(defaultMockData);
        expect(ReactNativeSiliconModule.generateSecureRandomBytes).toHaveBeenCalledOnce();
    });

    it("should throw when bridge result contains a Uint8Array but format is 'B64'", async () => {
        mockUint8ArrayResult();

        await expect(generateSecureRandomBytes(3, 'B64')).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateSecureRandomBytes).toHaveBeenCalledOnce();
    });

    it("should successfully return a string when format is 'B64URL'", async () => {
        const defaultMockData = mockStringResult();

        await expect(generateSecureRandomBytes(3, 'B64URL')).resolves.toBe(defaultMockData);
        expect(ReactNativeSiliconModule.generateSecureRandomBytes).toHaveBeenCalledOnce();
    });

    it("should throw when bridge result contains a Uint8Array but format is 'B64URL'", async () => {
        mockUint8ArrayResult();

        await expect(generateSecureRandomBytes(3, 'B64URL')).rejects.instanceOf(SiliconError);
        expect(ReactNativeSiliconModule.generateSecureRandomBytes).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()],
        { numRuns: 1000 }
    )('should throw when length is not of type number', async (chaoticData) => {
        const defaultMockData = mockUint8ArrayResult();
        
        if (isSafeNumber(chaoticData)) {
            await expect(generateSecureRandomBytes(chaoticData, 'BYTES')).resolves.toStrictEqual(defaultMockData);
            expect(ReactNativeSiliconModule.generateSecureRandomBytes).toHaveBeenCalledOnce();
        } else {
            // @ts-expect-error - intentionally pass incorrect type
            await expect(generateSecureRandomBytes(chaoticData, 'BYTES')).rejects.instanceOf(SiliconError);
            expect(ReactNativeSiliconModule.generateSecureRandomBytes).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [
            fc.oneof(
                fc.constant('BYTES'),
                fc.constant('B64'),
                fc.constant('B64URL'),
                fc.constant(undefined),
                fc.anything()
            )
        ],
        { numRuns: 1000 }
    )('should throw when format is not a valid string literal and is not undefined', async (chaoticData) => {
        if (chaoticData === 'BYTES' ||
            chaoticData === undefined
        ) {
            const defaultMockData = mockUint8ArrayResult();
            await expect(generateSecureRandomBytes(3, chaoticData)).resolves.toStrictEqual(defaultMockData);
            expect(ReactNativeSiliconModule.generateSecureRandomBytes).toHaveBeenCalledOnce();

        } else if (chaoticData === 'B64' ||
            chaoticData === 'B64URL'
        ) {
            const defaultMockData = mockStringResult();
            await expect(generateSecureRandomBytes(3, chaoticData)).resolves.toBe(defaultMockData);
            expect(ReactNativeSiliconModule.generateSecureRandomBytes).toHaveBeenCalledOnce();

        } else {
            // @ts-expect-error - intentionally passing invalid value
            await expect(generateSecureRandomBytes(3, chaoticData)).rejects.instanceOf(SiliconError);
            expect(ReactNativeSiliconModule.generateSecureRandomBytes).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });
});