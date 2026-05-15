import { Capabilities } from "./types";
import NativeSilicon from '../../module';
import { SiliconError, SiliconErrorCode } from "../../errors";

/**
 * Returns an object representing the capabilities of the device.
 */
export async function getCapabilities(): Promise<Capabilities> {
    const result = await NativeSilicon.getCapabilities()
    if (!result.success) {
        switch (result.errorCode) {
            case 'GET_CAPABILITIES_FAILED':
                throw new SiliconError(SiliconErrorCode.GET_CAPABILITIES_FAILED, result.errorMessage, { nativeStack: result.nativeStack })
            
            default:
                throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack })
        }
    }

    return result.data;
}
