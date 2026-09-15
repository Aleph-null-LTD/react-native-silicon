import { SiliconError, SiliconErrorCode } from "../errors";
import { BridgeResult } from "../types/bridge-result";

export function handleBridgeResult<T>(result: BridgeResult<T>): T {
    if (result.success) {
        return result.data;
    }
    
    const code: SiliconErrorCode | undefined = SiliconErrorCode[result.errorCode as SiliconErrorCode];
    if (code === undefined) {
        throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack });
    }
    
    throw new SiliconError(code, result.errorMessage, { nativeStack: result.nativeStack });
}