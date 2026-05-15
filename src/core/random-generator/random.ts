import { RandomBytesFormat, RandomGenFormatTypeMap } from "./types";
import NativeSilicon from '../../module';
import { SiliconError, SiliconErrorCode } from "../../errors";
import { isRandomBytesFormat, randomBytesFormats } from "./constants";

/**
 * Generates random bytes using the secure hardware random generator.
 * @param length The number of bytes 
 * @param format The format of the returned bytes:
 * * B64URL - Base64Url string (default)
 * * B64 - Standard Base64 string
 * * BYTES - Uint8Array of the bytes
 * @returns The formatted/raw random bytes
 */
export async function generateSecureRandomBytes<T extends RandomBytesFormat = typeof randomBytesFormats.B64URL>(length: number, format: T = randomBytesFormats.B64URL as T): Promise<RandomGenFormatTypeMap[T]> {
    if (typeof length !== 'number') throw new TypeError("Silicon Error: 'length' must be of type 'number'");
    
    if (typeof format !== 'string' || !isRandomBytesFormat(format)) {
        throw new TypeError(`Silicon Error: 'format' invalid, expected ${Object.values(randomBytesFormats).join("|")}`);
    }

    length = Math.round(length);

    const result = await NativeSilicon.generateSecureRandomBytes(length, format);
    if (!result.success) {
        if (result.errorCode == 'RANDOM_GEN_FAILED') {
            throw new SiliconError(SiliconErrorCode.RANDOM_GEN_FAILED, result.errorMessage, { nativeStack: result.nativeStack })    
        }
        throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack })
    }

    if (format == 'B64URL' || format == 'B64') {
        return result.data
    }
    if (format == 'BYTES') {
        return result.data
    }

    // Should never get here
    throw new Error(`Silicon Error: Invalid format ${format}`);
}

