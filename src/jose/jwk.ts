import { SignDigest } from '../core/operations';
import { isSignDigest, signDigest } from '../core/operations/constants';
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
    if (typeof alias != 'string' || alias.trim().length < 1) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] alias must be of type string");
    if (digest !== undefined && !isSignDigest(digest)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] digest must be of type ${Object.values(signDigest).join(' | ')}`);

    const result = await NativeSilicon.getJwk(alias, digest);
    return handleBridgeResult(result);
}
