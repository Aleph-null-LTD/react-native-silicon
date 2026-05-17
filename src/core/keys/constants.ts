import { createInSetGuard } from "../../utils/validation";

// Purposes
export const keyPurposes = {
    SIGN: 'SIGN', 
    VERIFY: 'VERIFY',
    ENCRYPT: 'ENCRYPT',
    DECRYPT: 'DECRYPT',
    WRAP: 'WRAP',
    AGREE: 'AGREE',
    ATTEST: 'ATTEST'
} as const;

const keyPurposeSet: ReadonlySet<keyof typeof keyPurposes> = new Set(Object.values(keyPurposes));

export const isKeyPurpose = createInSetGuard(keyPurposeSet);

// Digests
export const keyDigests = {
    SHA256: 'SHA256'
} as const;

const keyDigestSet: ReadonlySet<keyof typeof keyDigests> = new Set(Object.values(keyDigests));

export const isKeyDigest = createInSetGuard(keyDigestSet);

// User Auth Policies
export const userAuthPolicies = {
    BIOMETRICS_ONLY: 'BIOMETRICS_ONLY',
    BIOMETRICS_OR_CREDENTIAL: 'BIOMETRICS_OR_CREDENTIAL'
} as const;

const userAuthPolicySet: ReadonlySet<keyof typeof userAuthPolicies> = new Set(Object.values(userAuthPolicies));

export const isUserAuthPolicy = createInSetGuard(userAuthPolicySet);

// Pubkey formats
export const pubkeyFormats = {
    PEM: 'PEM',
    B64: 'B64'
} as const;

const pubkeyFormatSet: ReadonlySet<keyof typeof pubkeyFormats> = new Set(Object.values(pubkeyFormats));

export const isPubkeyFormat = createInSetGuard(pubkeyFormatSet);

// Android algorithms
export const androidAlgorithms = {
    ES256: 'ES256'
    /*
    ES512: 'ES512',
    ES512: 'ES512',
    RS256: 'RS256',
    MLDSA65: 'MLDSA65',
    MLDSA87: 'MLDSA87'
    */
} as const;

const androidAlgorithmSet: ReadonlySet<keyof typeof androidAlgorithms> = new Set(Object.values(androidAlgorithms));

export const isAndroidAlgorithm = createInSetGuard(androidAlgorithmSet);

// Android hardware policies
export const androidHardwarePolicies = {
    REQUIRE_STRONGBOX: 'REQUIRE_STRONGBOX',
    PREFER_STRONGBOX: 'PREFER_STRONGBOX',
    USE_TEE: 'USE_TEE'
} as const;

const androidHardwarePolicySet: ReadonlySet<keyof typeof androidHardwarePolicies> = new Set(Object.values(androidHardwarePolicies));

export const isAndroidHardwarePolicy = createInSetGuard(androidHardwarePolicySet);
