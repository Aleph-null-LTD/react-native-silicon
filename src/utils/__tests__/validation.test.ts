import { describe, it, expect } from "vitest";
import { test } from '@fast-check/vitest';
import fc from "fast-check";
import { createInSetGuard, isPlainObject } from "../validation";
import { fcCustomArbitraries } from "../../__test_utils__/fast-check/arbitraries";

describe('isPlainObject()', () => {
    test.prop(
        [fc.object()],
        { numRuns: 10000 }
    )('should return true when value is a plain object', (plainObj) => {
        expect(isPlainObject(plainObj)).toBe(true);
    });

    test.prop(
        [fcCustomArbitraries.anything.nonPlainObj()],
        { numRuns: 10000 }
    )('should return false when value is not a plain object', (plainObj) => {
        expect(isPlainObject(plainObj)).toBe(false);
    });
});

describe('createInSetGuard()', () => {
    const dummyStrSet = new Set(['random', 'strings', 'in', 'here']);
    const dummyNumSet = new Set([1, 2, 3, 4]);
    const dummyCombinedSet = new Set(['random', 'strings', 'in', 'here', 1, 2, 3, 4]);
    
    it('should return a function ref', () => {
        expect(createInSetGuard(dummyStrSet)).toBeTypeOf('function');
        expect(createInSetGuard(dummyNumSet)).toBeTypeOf('function');
        expect(createInSetGuard(dummyCombinedSet)).toBeTypeOf('function');
    });

    test.prop(
        [
            fc.oneof(
                fc.constant('random'), 
                fc.constant('strings'), 
                fc.constant('in'), 
                fc.constant('here'),
                fc.constant(1), 
                fc.constant(2), 
                fc.constant(3), 
                fc.constant(4),
                fc.anything()
            )
        ],
        { numRuns: 10000 }
    )('should return a function that correctly evaluates the enclosed Set', (chaoticData) => {
        const inStrSet = createInSetGuard(dummyStrSet);
        const inNumSet = createInSetGuard(dummyNumSet);
        const inCombinedSet = createInSetGuard(dummyCombinedSet);
        
        if (chaoticData === 'random' ||
            chaoticData === 'strings' ||
            chaoticData === 'in' ||
            chaoticData === 'here'
        ) {
            expect(inStrSet(chaoticData)).toBe(true);
            expect(inNumSet(chaoticData)).toBe(false);
            expect(inCombinedSet(chaoticData)).toBe(true);
            
        } else if (
            chaoticData === 1 ||
            chaoticData === 2 ||
            chaoticData === 3 ||
            chaoticData === 4
        ) { 
            expect(inStrSet(chaoticData)).toBe(false);
            expect(inNumSet(chaoticData)).toBe(true);
            expect(inCombinedSet(chaoticData)).toBe(true);

        } else {
            expect(inStrSet(chaoticData)).toBe(false);
            expect(inNumSet(chaoticData)).toBe(false);
            expect(inCombinedSet(chaoticData)).toBe(false);
        }
    });
});
