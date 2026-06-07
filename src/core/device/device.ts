import { Capabilities } from "./types";
import NativeSilicon from '../../module';
import { handleBridgeResult } from "../../utils/handle-bridge-result";

/**
 * Returns an object representing the capabilities of the device.
 */
export async function getCapabilities(): Promise<Capabilities> {
    const result = await NativeSilicon.getCapabilities()
    return handleBridgeResult(result);
}
