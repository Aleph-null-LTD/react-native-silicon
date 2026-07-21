import { SiliconError, SiliconErrorCode } from "../errors";

export function ensureUint8Array(data: unknown): Uint8Array {
    if (data instanceof Uint8Array) {
        return data;
    }
    
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data);
    }

    if (Array.isArray(data)) {
        const isValidByteArray = data.every(
            (element) => typeof element === 'number' && Number.isInteger(element) && element >= 0 && element <= 255
        );

        if (!isValidByteArray) {
            throw new SiliconError(
                SiliconErrorCode.INTERNAL_ERROR, 
                '[RN-Silicon] Failed to convert Array to Uint8Array: Array contains invalid bytes (must be integers 0-255).'
            );
        }

        return new Uint8Array(data);
    }

    throw new SiliconError(SiliconErrorCode.INTERNAL_ERROR, `[RN-Silicon] Failed to convert returned data to Uint8Array. Got type ${typeof data}`)
}
