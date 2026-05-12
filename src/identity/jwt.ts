import { sign } from "../core/operations/operations";

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

function objectToBase64Url(obj: object): string {
  // Stringify the object to JSON
  const jsonStr = JSON.stringify(obj);

  let standardBase64;

  // Safely encode UTF-8 characters and convert to standard Base64.
  // Check if TextEncoder is present and use that if available, if not fallback to the legacy supported path
  if (typeof TextEncoder !== 'undefined') {
    const bytes = new TextEncoder().encode(jsonStr);
    
    // Convert Uint8Array to a binary string safely
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
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
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
export async function signJwt(alias: string, header: JwtHeader, payload: JwtPayload, opts): Promise<string> {
    // Encode the Header and Payload, then concat them with a '.' seperator
    const encodedHeader = objectToBase64Url(header);
    const encodedPayload = objectToBase64Url(payload);
    const signInput = `${encodedHeader}.${encodedPayload}`;
    
    // Generate the signature
    const signature = await sign(alias, signInput, opts.algorithm, { encoding: 'B64_URL' });
    
    // Concat the signature
    return `${signInput}.${signature}`
}
