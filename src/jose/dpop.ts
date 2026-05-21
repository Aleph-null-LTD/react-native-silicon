import { isSignDigest, signDigest } from "../core/operations/constants";
import { generateSecureRandomBytes } from "../core/random-generator";
import { hasOwn } from "../utils/validation";
import { getJwk } from "./jwk";
import { signJwt } from "./jwt";
import { GenerateDpopProofOpts } from "./types";

/**
 * Generates a RFC 9449 compliant, signed DPoP proof JWT using the key specified by 'alias'
 * @param alias 
 * @param opts 
 * @returns the signed DPoP proof JWT
 */
export async function generateDpopProof(alias: string, opts: GenerateDpopProofOpts): Promise<string> {
    if (typeof alias !== 'string') throw new TypeError("Silicon Error: 'alias' must be of type 'string'");
    
    if (!hasOwn(opts, 'htu')) throw new TypeError("Silicon Error: 'opts.htu' is required");
    if (typeof opts.htu !== 'string') throw new TypeError("Silicon Error: 'opts.htu' must be of type 'string'");
    
    // Parse and normalize the htu
    const parsedHtu = new URL(opts.htu);
    const normalizedHtu = `${parsedHtu.protocol}//${parsedHtu.host}${parsedHtu.pathname}`;

    if (!hasOwn(opts, 'htm')) throw new TypeError("Silicon Error: 'opts.htm' is required");
    if (typeof opts.htu !== 'string') throw new TypeError("Silicon Error: 'opts.htm' must be of type 'string'");
    
    const htmUpper = opts.htm.toUpperCase();

    if (hasOwn(opts, 'digest') &&
        opts.digest !== undefined &&
        (typeof opts.digest !== 'string' || !isSignDigest(opts.digest))
    ) {
        throw new TypeError(`Silicon Error: 'opts.digest' must be of type ${Object.values(signDigest).join('|')}`);
    }

    let jti: string;
    if (hasOwn(opts, 'jti') &&
        opts.jti !== undefined
    ) {
        if (typeof opts.jti !== 'string') throw new TypeError("Silicon Error: 'opts.jti' must be of type 'string'");
        jti = opts.jti;
    } else {
        // Default the jti to 16 random bytes Base64Url encoded
        jti = await generateSecureRandomBytes(16, 'B64URL');
    }

    if (hasOwn(opts, 'nonce') &&
        opts.nonce !== undefined &&
        typeof opts.nonce !== 'string'
    ) {
        throw new TypeError("Silicon Error: 'opts.nonce' must be of type 'string'");
    }
    
    const jwk = await getJwk(alias);
    
    // Strip the alg out of the JWK so we can store it in the header seperately
    const alg = jwk.alg;
    delete jwk.alg;
    if (typeof alg !== 'string') throw new TypeError("Silicon Error: Internal Error: 'alg' was not of type 'string'. Please report this error at https://github.com/Aleph-null-LTD/react-native-silicon/issues")
    
    // Generate the iat timestamp (in seconds)
    const iat = Math.floor(Date.now() / 1000);

    const dpopProofJwt = await signJwt(
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

    return dpopProofJwt;
}
