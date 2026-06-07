import { SiliconError, SiliconErrorCode } from "../errors";

export function ensureUint8Array(data: unknown): Uint8Array {
    if (data instanceof Uint8Array) {
        return data;
    }
    
    if (Array.isArray(data) || data instanceof ArrayBuffer) {
        return new Uint8Array(data);
    }

    throw new SiliconError(SiliconErrorCode.INTERNAL_ERROR, `[RN-Silicon] Failed to convert returned data to Uint8Array. Got type ${typeof data}`)
}
