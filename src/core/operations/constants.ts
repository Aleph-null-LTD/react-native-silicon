import { createInSetGuard } from "../../utils/validation";

// ---- Sign ----

// Encodings
export const signEncodings = {
    B64URL: 'B64URL',
    B64: 'B64'
} as const;

const signEncodingSet: ReadonlySet<keyof typeof signEncodings> = new Set(Object.values(signEncodings));

export const isSignEncoding = createInSetGuard(signEncodingSet);

// Digest
export const signDigest = {
    SHA256: 'SHA256',
    SHA384: 'SHA384',
    SHA512: 'SHA512'
} as const;

const signDigestsSet: ReadonlySet<keyof typeof signDigest> = new Set(Object.values(signDigest));

export const isSignDigest = createInSetGuard(signDigestsSet);

// Format
export const signFormats = {
    P1363: 'P1363',
    DER: 'DER'
} as const;

const signFormatsSet: ReadonlySet<keyof typeof signFormats> = new Set(Object.values(signFormats));

export const isSignFormat = createInSetGuard(signFormatsSet);

// ---- Verify ----

// Algorithms
export const verifyAlgorithms = {
    ES256: 'ES256',
    ES384: 'ES384',
    ES512: 'ES512',
    RS256: 'RS256',
    RS384: 'RS384',
    RS512: 'RS512',
    PS256: 'PS256',
    PS384: 'PS384',
    PS512: 'PS512'
} as const;

const verifyAlgorithmsSet: ReadonlySet<keyof typeof verifyAlgorithms> = new Set(Object.values(verifyAlgorithms));

export const isVerifyAlgorithm = createInSetGuard(verifyAlgorithmsSet);
