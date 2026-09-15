import fc from "fast-check";

class CustomTestClass {
    constructor(public id: string) {}
}

export const fcCustomArbitraries = {
    primatives: () => fc.oneof(
        // Primitives & Null
        fc.string(),
        fc.integer(),
        fc.double(),
        fc.float(),
        fc.bigInt(),
        fc.boolean(),
        fc.constant(-0),
        fc.constant(NaN),
        fc.constant(Infinity),
        fc.constant(-Infinity),
        fc.constant(null),
        fc.constant(undefined),
        fc.string().map(str => Symbol(str)),
    ),
    anything: {
        nonPlainObj: () => fc.oneof(
            // Primitives
            { weight: 13, arbitrary: fcCustomArbitraries.primatives() },
            
            // Functions
            fc.func(fc.anything()),

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
        ),
        nonArray: () => fc.oneof(
            // Primitives & Null
            { weight: 13, arbitrary: fcCustomArbitraries.primatives() },

            // Functions
            fc.func(fc.anything()),

            // Plain Objects
            fc.object(),
            
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
        ),
    },
    number: {
        positive: () => fc.oneof(
            fc.integer().filter((data) => data > 0),
            fc.float().filter((data) => data > 0),
            fc.double().filter((data) => data > 0)
        ),
        negative: () => fc.oneof(
            fc.integer().filter((data) => data < 0),
            fc.float().filter((data) => data < 0),
            fc.double().filter((data) => data < 0)
        ),
        nonZero: () => fc.oneof(
            fc.integer().filter((data) => !Object.is(data, 0) && !Object.is(data, -0)),
            fc.float().filter((data) => !Object.is(data, 0) && !Object.is(data, -0)),
            fc.double().filter((data) => !Object.is(data, 0) && !Object.is(data, -0))
        )
    }
};
