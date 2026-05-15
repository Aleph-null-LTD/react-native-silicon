import { signAlgorithms, signEncodings, signFormats, verifyAlgorithms } from "./constants";

// ---- Sign ----

export type SignEncodings = keyof typeof signEncodings;
export type SignAlgorithms = keyof typeof signAlgorithms;
export type SignFormats = keyof typeof signFormats;

export interface SignOpts {
    /**
     * The encoding to use for the signature.
     * @default B64_URL
     */
    encoding: SignEncodings;
    
    /**
     * The algorithm to use for the signature
     * @default SHA256
     */
    algorithm?: SignAlgorithms;

    /**
     * Output format of the signature bytes when signing with an EC key.
     * @default 'P1363' // (Standard WebCrypto / JWT format)
     * @note Set to 'DER' if interacting with legacy Java/ASN.1 backend systems.
     */
    format?: SignFormats;
};

// ---- Verify ----

export type VerifyAlgorithms = keyof typeof verifyAlgorithms;

export interface InternalVerifyOpts {
    /**
     * The alias of the key to verify the signature against
     */
    alias: string;

    /**
     * The algorithm to use for the verification
     */
    algorithm: VerifyAlgorithms;
};

export interface ExternalVerifyOpts {
    /**
     * The pubkey to verify the signature against
     */
    pubkey: string;

    /**
     * The algorithm to use for the verification
     */
    algorithm: VerifyAlgorithms;
};

export type VerifyOpts = InternalVerifyOpts | ExternalVerifyOpts;

/**
 * Options that will be passed to the Native bridge
 */
export interface BridgeVerifyOpts {
    alias: string | undefined;
    pubkeyB64: string | undefined;
    algorithm: VerifyAlgorithms;
}
