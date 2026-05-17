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
    SHA256: 'SHA256'
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
    ES256: 'ES256'
} as const;

const verifyAlgorithmsSet: ReadonlySet<keyof typeof verifyAlgorithms> = new Set(Object.values(verifyAlgorithms));

export const isVerifyAlgorithm = createInSetGuard(verifyAlgorithmsSet);
