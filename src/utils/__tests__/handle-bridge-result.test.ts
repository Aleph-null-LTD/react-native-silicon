import { describe, expect, it } from "vitest";
import { handleBridgeResult } from "../handle-bridge-result";
import { createBridgeSuccess, createBridgeFailure } from "../../__test_utils__/factories/bridge-result";
import { test } from "@fast-check/vitest";
import fc from "fast-check";
import { SiliconError, SiliconErrorCode } from "../../errors";

describe('handleBridgeResult()', () => {
    test.prop(
        [fc.anything()],
        { numRuns: 10000 }
    )('should return the extracted data from BridgeResult when it is a success', (chaoticData) => {
        expect(
            handleBridgeResult(createBridgeSuccess(chaoticData))
        ).toBe(chaoticData)
    });
    
    it('should throw when BridgeResult is a failure', () => {
        expect(
            () => handleBridgeResult(createBridgeFailure(SiliconErrorCode.INTERNAL_ERROR, "some random error message", "some-random-native-stack"))
        ).toThrow(SiliconError);
    });
});
