import { createInSetGuard } from "../../utils/validation";

// ---- Sign ----

// Encodings
export const signEncodings = {
    B64_URL: 'B64_URL',
    B64: 'B64'
} as const;

export const signEncodingSet: ReadonlySet<keyof typeof signEncodings> = new Set(Object.values(signEncodings));

export const isSignEncoding = createInSetGuard(signEncodingSet);

// Algorithms
export const signAlgorithms = {
    'SHA256': 'SHA256'
} as const;

export const signAlgorithmsSet: ReadonlySet<keyof typeof signAlgorithms> = new Set(Object.values(signAlgorithms));

export const isSignAlgorithm = createInSetGuard(signAlgorithmsSet);

// ---- Verify ----

// Algorithms
export const verifyAlgorithms = {
    ES256: 'ES256'
} as const;

export const verifyAlgorithmsSet: ReadonlySet<keyof typeof verifyAlgorithms> = new Set(Object.values(verifyAlgorithms));

export const isVerifyAlgorithm = createInSetGuard(verifyAlgorithmsSet);
