import { SignDigest } from '../core/operations';
import { SiliconError, SiliconErrorCode } from '../errors';
import NativeSilicon from '../module';
import { handleBridgeResult } from '../utils/handle-bridge-result';
import { Jwk } from './types';

/**
 * Gets a JSON Web Key (JWK) from the key specified by 'alias'
 * @param alias 
 * @returns 
 */
export async function getJwk(alias: string, digest?: SignDigest): Promise<Jwk> {
    if (typeof alias !== 'string') throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] alias must be of type string");
    
    const result = await NativeSilicon.getJwk(alias, digest);
    return handleBridgeResult(result);
}
