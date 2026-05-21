import { SignDigest } from "../core/operations";

export interface JwkEC {
    kty: "EC";
    crv: string;
    x: string;
    y: string;
    alg: string;
    [key: string]: unknown;
};

export interface JwkRSA {
    kty: "RSA",
    n: string,
    e: string
    alg: string;
    [key: string]: unknown;
};

export type Jwk = JwkEC | JwkRSA | Record<string, unknown>;
    

export interface JwtHeader {
    typ?: "JWT" | "dpop+jwt" | string;
    alg?: string;
    jwk?: Jwk;// JSON Web Key
    [key: string]: unknown; // Allow custom header claims like 'kid'
};

export interface JwtPayload {
    iss?: string; // Issuer
    sub?: string; // Subject
    aud?: string; // Audience
    exp?: number; // Expiration time (Epoch seconds)
    nbf?: number; // Not before
    iat?: number; // Issued at
    jti?: string; // JWT ID 
    [key: string]: unknown; // Custom application claims
};

export type GenerateDpopProofOpts = {
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
    nonce?: string
};
