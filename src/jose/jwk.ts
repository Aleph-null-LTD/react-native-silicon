import { SiliconError, SiliconErrorCode } from '../errors';
import NativeSilicon from '../module';
import { Jwk } from './types';

/**
 * Gets a JSON Web Key (JWK) from the key specified by 'alias'
 * @param alias 
 * @returns 
 */
export async function getJwk(alias: string): Promise<Jwk> {
    if (typeof alias !== 'string') throw new TypeError("Silicon Error: 'alias' must be of type 'string'");
    
    const result = await NativeSilicon.getJwk(alias);
    if (!result.success) {
        switch (result.errorCode) {
            case "KEY_NOT_FOUND":
                throw new SiliconError(SiliconErrorCode.KEY_NOT_FOUND, result.errorMessage, { nativeStack: result.nativeStack });

            case "UNSUPPORTED_KEY_FAMILY":
                throw new SiliconError(SiliconErrorCode.UNSUPPORTED_KEY_FAMILY, result.errorMessage, { nativeStack: result.nativeStack });

            case "NO_CERT":
                throw new SiliconError(SiliconErrorCode.NO_CERT, result.errorMessage, { nativeStack: result.nativeStack });

            case "GET_JWK_FAILED":
                throw new SiliconError(SiliconErrorCode.GET_JWK_FAILED, result.errorMessage, { nativeStack: result.nativeStack });

            default: 
                throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack });
        }
    }

    return result.data;
}
