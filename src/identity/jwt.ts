import { SignAlgorithms } from "../core/operations";
import { isSignAlgorithm } from "../core/operations/constants";
import { sign } from "../core/operations/operations";
import { isPlainObject } from "../utils/validation";

export interface JwtHeader {
    alg: 'ES256' | 'RS256';
    typ?: 'JWT';
    [key: string]: any; // Allow custom header claims like 'kid'
}

export interface JwtPayload {
    iss?: string; // Issuer
    sub?: string; // Subject
    aud?: string; // Audience
    exp?: number; // Expiration time (Epoch seconds)
    nbf?: number; // Not before
    iat?: number; // Issued at
    [key: string]: any; // Custom application claims
}

/**
 * Sign a JWT using the specified key
 * 
 * @param alias 
 * @param header 
 * @param payload 
 * @param opts 
 * @returns The signed JWT
 */
export async function signJwt(alias: string, header: JwtHeader, payload: JwtPayload, algorithm?: SignAlgorithms): Promise<string> {
    if (typeof alias !== 'string') throw new TypeError();
    if (!isPlainObject(header)) throw new TypeError();
    if (!isPlainObject(payload)) throw new TypeError();
  
    if (algorithm &&
      (typeof algorithm !== 'string' || !isSignAlgorithm(algorithm))
    ) {
      throw new TypeError("");
    }

    if (!algorithm) {
      algorithm = 'SHA256';
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
        encoding: 'B64_URL',
        algorithm: algorithm,
        format: 'P1363'
      }
    );
    
    // Concat the signature
    return `${signInput}.${signature}`
}

const PLUS_REGEX = /\+/g;
const SLASH_REGEX = /\//g;
const EQUALS_REGEX = /=+$/;

function objectToBase64Url(obj: object): string {
    // Stringify the object to JSON
    const jsonStr = JSON.stringify(obj);

    let standardBase64;

    // Safely encode UTF-8 characters and convert to standard Base64.
    // Check if TextEncoder is present and use that if available, if not fallback to the legacy supported path
    if (typeof TextEncoder !== 'undefined') {
      const bytes = new TextEncoder().encode(jsonStr);
    
      // Convert Uint8Array to a binary string
      const binString = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
    
      standardBase64 = btoa(binString);
    } else {
      // Legacy Path: Fallback to the encodeURIComponent trick

      // eslint-disable-next-line no-redeclare, deprecation/deprecation
      const utf8Str = unescape(encodeURIComponent(jsonStr));
    
      standardBase64 = btoa(utf8Str);
    }

    // Convert to strict Base64URL (swap chars, strip padding =)
    return standardBase64
      .replace(PLUS_REGEX, '-')
      .replace(SLASH_REGEX, '_')
      .replace(EQUALS_REGEX, '');
}