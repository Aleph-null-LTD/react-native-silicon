import { BridgeResult } from "../../types/bridge-result";

export function createBridgeSuccess<T>(data: T): BridgeResult<T> {
    return {
        success: true,
        data: data
    };
}

export function createBridgeFailure(errorCode: string, errorMessage: string, nativeStack: string | null): BridgeResult<never> {
    return {
        success: false,
        errorCode,
        errorMessage,
        nativeStack
    };
}
