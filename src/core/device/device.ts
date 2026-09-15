import { Capabilities } from "./types";
import NativeSilicon from '../../module';
import { handleBridgeResult } from "../../utils/handle-bridge-result";
import { SiliconError, SiliconErrorCode } from "../../errors";

/**
 * Returns an object representing the capabilities of the mobile device.
 */
export async function getCapabilities(): Promise<Capabilities> {
    try {
        const result = await NativeSilicon.getCapabilities();
        return handleBridgeResult(result);
    } catch (error) {
        throw new SiliconError(SiliconErrorCode.INTERNAL_ERROR, "[RN-Silicon] getCapabilities failed with an internal error.", { cause: error })
    }
}
