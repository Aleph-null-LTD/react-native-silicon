import { describe, it, expect } from 'vitest';
import { SiliconError, SiliconErrorCode } from '../errors'

describe('SiliconError', () => {
    const errorNestedCause = new SiliconError(
        SiliconErrorCode.UNKNOWN_NATIVE_ERROR, 
        'Some nested cause dummy error message', 
        { nativeStack: 'nested-cause-dummy-stack-trace' }
    );
    
    const errorCause = new SiliconError(
        SiliconErrorCode.UNKNOWN_NATIVE_ERROR, 
        'Some cause dummy error message', 
        { cause: errorNestedCause, nativeStack: 'cause-dummy-stack-trace' }
    );
    
    const error = new SiliconError(
        SiliconErrorCode.UNKNOWN_NATIVE_ERROR, 
        'Some dummy error message', 
        { cause: errorCause }
    );

    describe('toJSON()', () => {
        it('should return a POJO with all the relevant properties', () => {        
            const pojo = error.toJSON();

            expect(
                pojo
            ).toEqual(
                { 
                    name: error.name,
                    stack: error.stack,
                    nativeStack: undefined,
                    code: error.code,
                    message: error.message,
                    cause: {
                        name: errorCause.name,
                        stack: errorCause.stack,
                        nativeStack: errorCause.nativeStack,
                        code: errorCause.code,
                        message: errorCause.message,
                        cause: {
                            name: errorNestedCause.name,
                            stack: errorNestedCause.stack,
                            nativeStack: errorNestedCause.nativeStack,
                            code: errorNestedCause.code,
                            message: errorNestedCause.message,
                            cause: undefined
                        }
                    }
                }
            );
        });
    });

    /*
    describe('serialize()', () => {
        it('should return a JSON string with all the relevant properties', () => {
            const jsonStr = error.serialize();

            expect(jsonStr).toBe(JSON.stringify(combinedErrorPojo))
        });
    });
    */
});