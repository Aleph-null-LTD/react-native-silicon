import { RandomBytesFormat, RandomGenFormatTypeMap } from "./types";
import NativeSilicon from '../../module';
import { SiliconError, SiliconErrorCode } from "../../errors";
import { isRandomBytesFormat, randomBytesFormats } from "./constants";
import { ensureUint8Array } from "../../utils/bytes";
import { handleBridgeResult } from "../../utils/handle-bridge-result";
import { isSafeNumber } from "../../utils/validation";

/**
 * Generates random bytes using the secure hardware random generator.
 * @param length The number of bytes 
 * @param format The format of the returned bytes:
 * * B64URL - Base64Url string
 * * B64 - Standard Base64 string
 * * BYTES - Uint8Array of the bytes (default)
 * @returns The formatted/raw random bytes
 */
export async function generateSecureRandomBytes<T extends RandomBytesFormat = typeof randomBytesFormats.BYTES>(length: number, format: T = randomBytesFormats.BYTES as T): Promise<RandomGenFormatTypeMap[T]> {
    if (!isSafeNumber(length)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] length must be of type number");
    
    if (typeof format !== 'string' || !isRandomBytesFormat(format)) {
        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] format invalid, expected ${Object.values(randomBytesFormats).join("|")}`);
    }

    length = Math.round(length);

    const result = await NativeSilicon.generateSecureRandomBytes(length, format);
    const randomBytes = handleBridgeResult(result);

    let ret: RandomGenFormatTypeMap[T];
    
    if (format === "BYTES") {
        ret = ensureUint8Array(randomBytes) as RandomGenFormatTypeMap[T];
    } else { // "B64" and "B64URL"
        if (typeof randomBytes !== 'string') throw new SiliconError(SiliconErrorCode.INTERNAL_ERROR, `[RN-Silicon] bridge returned a non-string result (type: ${typeof randomBytes}) for format ${format}`);
        ret = randomBytes;
    }

    return ret;
}

