
export interface JwkEC {
    kty: "EC";
    crv: string;
    x: string;
    y: string;
    alg: string;
    [key: string]: any;
}

export interface JwkRSA {
    kty: "RSA",
    n: string,
    e: string
    alg: string;
    [key: string]: any;
}

export type Jwk = JwkEC | JwkRSA | Record<string, any>;
    

export interface JwtHeader {
    typ?: "JWT" | "dpop+jwt" | string;
    alg?: "ES256" | "RS256";
    jwk?: Jwk;// JSON Web Key
    [key: string]: any; // Allow custom header claims like 'kid'
}

export interface JwtPayload {
    iss?: string; // Issuer
    sub?: string; // Subject
    aud?: string; // Audience
    exp?: number; // Expiration time (Epoch seconds)
    nbf?: number; // Not before
    iat?: number; // Issued at
    jti?: string; // JWT ID 
    [key: string]: any; // Custom application claims
}
