import { signDigest, signEncodings, signFormats, verifyAlgorithms } from "./constants";

// ---- Sign ----

export type SignEncodings = keyof typeof signEncodings;
export type SignDigest = keyof typeof signDigest;
export type SignFormats = keyof typeof signFormats;

export type SignOpts = {
    /**
     * The encoding to use for the signature.
     * @default B64_URL
     */
    encoding: SignEncodings,
    
    /**
     * The algorithm to use for the signature
     * **Default**: Matches the size of the key algorithm (e.g., "SHA256" for "ES256").
     * @note This MUST be one of the allowed digests 
     */
    digest?: SignDigest,

    /**
     * Output format of the signature bytes when signing with an EC key.
     * @default 'P1363' // (Standard WebCrypto / JWT format)
     * @note Set to 'DER' if interacting with legacy Java/ASN.1 backend systems.
     */
    format?: SignFormats
};

// ---- Verify ----

export type VerifyAlgorithms = keyof typeof verifyAlgorithms;

export type InternalVerifyOpts = {
    /**
     * The alias of the key to verify the signature against
     */
    alias: string,

    /**
     * The algorithm to use for the verification
     */
    algorithm: VerifyAlgorithms
};

export type ExternalVerifyOpts = {
    /**
     * The pubkey to verify the signature against
     */
    pubkey: string,

    /**
     * The algorithm to use for the verification
     */
    algorithm: VerifyAlgorithms
};

export type VerifyOpts = InternalVerifyOpts | ExternalVerifyOpts;

/**
 * Options that will be passed to the Native bridge
 */
export type BridgeVerifyOpts = {
    alias: string | undefined,
    pubkeyB64: string | undefined,
    algorithm: VerifyAlgorithms
}
