import { RandomBytesFormat, RandomGenFormatTypeMap } from "./types";
import NativeSilicon from '../../module';
import { SiliconError, SiliconErrorCode } from "../../errors";
import { isRandomBytesFormat, randomBytesFormats } from "./constants";
import { ensureUint8Array } from "../../utils/bytes";
import { handleBridgeResult } from "../../utils/handle-bridge-result";

/**
 * Generates random bytes using the secure hardware random generator.
 * @param length The number of bytes 
 * @param format The format of the returned bytes:
 * * B64URL - Base64Url string (default)
 * * B64 - Standard Base64 string
 * * BYTES - Uint8Array of the bytes
 * @returns The formatted/raw random bytes
 */
export async function generateSecureRandomBytes<T extends RandomBytesFormat = typeof randomBytesFormats.BYTES>(length: number, format: T = randomBytesFormats.BYTES as T): Promise<RandomGenFormatTypeMap[T]> {
    if (typeof length !== 'number') throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] 'length' must be of type 'number'");
    
    if (typeof format !== 'string' || !isRandomBytesFormat(format)) {
        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] 'format' invalid, expected ${Object.values(randomBytesFormats).join("|")}`);
    }

    length = Math.round(length);

    const result = await NativeSilicon.generateSecureRandomBytes(length, format);
    const randomBytes = handleBridgeResult(result);

    let ret: RandomGenFormatTypeMap[T];
    
    if (format === "BYTES") {
        ret = ensureUint8Array(randomBytes) as RandomGenFormatTypeMap[T];
    } else {
        ret = randomBytes;
    }

    return ret;
}

