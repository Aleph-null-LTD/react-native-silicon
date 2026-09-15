import { describe, expect } from "vitest";
import { test } from "@fast-check/vitest";
import fc from "fast-check";
import { ensureUint8Array } from "../bytes";
import { SiliconError } from "../../errors";
import { isSafeNumber } from "../validation";

describe('ensureUint8Array()', () => {
    test.prop(
        [fc.uint8Array()],
        { numRuns: 10000 }
    )('should successfully return the exact data when data is Uint8Array', (validData) => {
        const result = ensureUint8Array(validData);
        
        expect(result).toBeInstanceOf(Uint8Array);
        expect(result).toEqual(validData);
    });
    
    test.prop(
        [fc.uint8Array()],
        { numRuns: 10000 }
    )('should successfully convert arrays of valid bytes', (validData) => {
        const arr = Array.from(validData);
        const result = ensureUint8Array(arr);
        
        expect(result).toBeInstanceOf(Uint8Array);
        expect(result).toEqual(validData);
    });

    test.prop(
        [
            fc.array(
                fc.anything().filter((data) => !isSafeNumber(data)), 
                { 
                    minLength: 1 
                }
            )
        ],
        { numRuns: 10000 }
    )('should throw when an array contains invalid data types', (invalidArray) => {
        expect(() => ensureUint8Array(invalidArray)).toThrow(SiliconError);
    });
    
    test.prop(
        [
            fc.anything().filter((data) => !(data instanceof Uint8Array || Array.isArray(data) || data instanceof ArrayBuffer))
        ],
        { numRuns: 10000 }
    )('should throw when data is not a Uint8Array, Array, or ArrayBuffer', (chaoticData) => {
        expect(() => ensureUint8Array(chaoticData)).toThrow(SiliconError);
    });
});
