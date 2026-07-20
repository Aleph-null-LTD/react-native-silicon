import { SignDigest } from "../core/operations";
import { isSignDigest, signDigest } from "../core/operations/constants";
import { sign } from "../core/operations/operations";
import { SiliconError, SiliconErrorCode } from "../errors";
import { objectToBase64Url } from "../utils/encoding";
import { isPlainObject } from "../utils/validation";
import { JwtHeader, JwtPayload } from "./types";

/**
 * Sign a JWT using the specified key
 * 
 * @param alias 
 * @param header 
 * @param payload 
 * @param digest 
 * @returns The signed JWT
 */
export async function signJwt(alias: string, header: JwtHeader, payload: JwtPayload, digest?: SignDigest): Promise<string> {
    if (typeof alias !== 'string' || alias.trim().length < 1) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] alias must be of type string");
    if (!isPlainObject(header)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] header must be an object");
    if (!isPlainObject(payload)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] payload must be an object");
  
    if (digest !== undefined &&
      (typeof digest !== 'string' || !isSignDigest(digest))
    ) {
      console.log("in here")
      throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] digest must be of type ${Object.values(signDigest).join("|")}`);
    }
  
    // Encode the Header and Payload, then concat them with a '.' seperator
    const encodedHeader = objectToBase64Url(header);
    const encodedPayload = objectToBase64Url(payload);
    const signInput = `${encodedHeader}.${encodedPayload}`;
    
    // Generate the signature
    const signature = await sign(
      alias, 
      signInput,
      { 
        encoding: 'B64URL',
        digest: digest,
        format: 'P1363'
      }
    );
    
    // Concat the signature
    return `${signInput}.${signature}`
}

