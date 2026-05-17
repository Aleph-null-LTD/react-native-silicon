import { SignDigest } from "../core/operations";
import { isSignDigest, signDigest } from "../core/operations/constants";
import { generateSecureRandomBytes } from "../core/random-generator";
import { hasOwn } from "../utils/validation";
import { getJwk } from "./jwk";
import { signJwt } from "./jwt";

interface GenerateDpopProofOpts {
    /**
     * The digest algorithm to use when signing the JWT
     * 
     * **Default**: Matches the size of the key algorithm (e.g., "SHA256" for "ES256").
     * @note This MUST be one of the allowed digests 
     */
    digest?: SignDigest
    
    /**
     * HTTP URL (e.g., "https://your.domain/some/path")
     */
    htu: string,
    
    /**
     * HTTP method (e.g., "POST")
     * @note Must be uppercase and will be automatically converted to uppercase if it is not
     */
    htm: string,

    /**
     * JWT ID: A case-sensitive unique identifier for the JWT
     * 
     * **Default:** A secure random generated 16 byte Base64Url encoded string
     */
    jti?: string,

    /**
     * Optional nonce claim
     */
    nonce?: string,
}

/**
 * Generates a RFC 9449 compliant, signed DPoP proof JWT using the key specified by 'alias'
 * @param alias 
 * @param opts 
 */
export async function generateDpopProof(alias: string, opts: GenerateDpopProofOpts) {
    if (typeof alias !== 'string') throw new TypeError("Silicon Error: 'alias' must be of type 'string'");
    
    if (!hasOwn(opts, 'htu')) throw new TypeError("Silicon Error: 'opts.htu' is required");
    if (typeof opts.htu !== 'string') throw new TypeError("Silicon Error: 'opts.htu' must be of type 'string'");
    
    // Parse and normalize the htu
    const parsedHtu = new URL(opts.htu);
    const normalizedHtu = `${parsedHtu.protocol}//${parsedHtu.host}${parsedHtu.pathname}`;

    if (!hasOwn(opts, 'htm')) throw new TypeError("Silicon Error: 'opts.htm' is required");
    if (typeof opts.htu !== 'string') throw new TypeError("Silicon Error: 'opts.htm' must be of type 'string'");
    
    const htmUpper = opts.htm.toUpperCase();

    if (hasOwn(opts, 'digest')) {
        if (typeof opts.digest !== 'string' || !isSignDigest(opts.digest)) {
            throw new TypeError(`Silicon Error: 'opts.digest' must be of type ${Object.values(signDigest).join('|')}`);
        }
    }

    let jti: string;
    if (hasOwn(opts, 'jti')) {
        if (typeof opts.jti !== 'string') throw new TypeError("Silicon Error: 'opts.jti' must be of type 'string'");
        jti = opts.jti;
    } else {
        // Default the jti to 16 random bytes Base64Url encoded
        jti = await generateSecureRandomBytes(16, 'B64URL');
    }
    
    const jwk = await getJwk(alias);
    
    // Strip the alg out of the JWK so we can store it in the header seperately
    const alg = jwk.alg;
    delete jwk.alg;
    
    // Generate the iat timestamp (in seconds)
    const iat = Math.round(Date.now() / 1000);

    signJwt(
        alias,
        {
            typ: 'dpop+jwt',
            alg: alg,
            jwk: jwk
        },
        {
            htu: normalizedHtu,
            htm: htmUpper,
            jti: jti,
            iat: iat,
            nonce: opts.nonce
        },
        opts.digest
    );
}
