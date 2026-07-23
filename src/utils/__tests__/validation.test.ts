import { describe, it, expect } from "vitest";
import { test } from '@fast-check/vitest';
import fc from "fast-check";
import { createInSetGuard, isPlainObject } from "../validation";

class CustomTestClass {
    constructor(public id: string) {}
}

describe('isPlainObject()', () => {
    test.prop(
        [fc.object()]
    )('should return true when value is a plain object', (plainObj) => {
        expect(isPlainObject(plainObj)).toBe(true);
    });

    test.prop(
        [
            fc.oneof(
                // Primitives & Null
                fc.string(),
                fc.integer(),
                fc.boolean(),
                fc.constant(null),
                fc.constant(undefined),
                
                // Standard Arrays
                fc.array(fc.anything()),
                
                // Complex Built-in Objects
                fc.date(),
                fc.uint8Array(),
                fc.array(fc.string()).map(arr => new Set(arr)),
                fc.dictionary(fc.string(), fc.string()).map(obj => new Map(Object.entries(obj))),
                
                // Custom Class Instances
                fc.uuid().map(
                    (id) => {
                        return new CustomTestClass(id)
                    }
                )
            )
        ]
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
        ]
    )('should return a function that correctly evaluates the enclosed Set', (chaoticData) => {
        const inStrSetGuard = createInSetGuard(dummyStrSet);
        const inNumSetGuard = createInSetGuard(dummyNumSet);
        const inCombinedSetGuard = createInSetGuard(dummyCombinedSet);
        
        if (chaoticData === 'random' ||
            chaoticData === 'strings' ||
            chaoticData === 'in' ||
            chaoticData === 'here'
        ) {
            expect(inStrSetGuard(chaoticData)).toBe(true);
            expect(inNumSetGuard(chaoticData)).toBe(false);
            expect(inCombinedSetGuard(chaoticData)).toBe(true);
            
        } else if (
            chaoticData === 1 ||
            chaoticData === 2 ||
            chaoticData === 3 ||
            chaoticData === 4
        ) { 
            expect(inStrSetGuard(chaoticData)).toBe(false);
            expect(inNumSetGuard(chaoticData)).toBe(true);
            expect(inCombinedSetGuard(chaoticData)).toBe(true);

        } else {
            expect(inStrSetGuard(chaoticData)).toBe(false);
            expect(inNumSetGuard(chaoticData)).toBe(false);
            expect(inCombinedSetGuard(chaoticData)).toBe(false);
        }
    });
});
