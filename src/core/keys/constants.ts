import { createInSetGuard } from "../../utils/validation";

// Purposes
export const keyPurposes = {
    SIGN: 'SIGN', 
    VERIFY: 'VERIFY',
    ENCRYPT: 'ENCRYPT',
    DECRYPT: 'DECRYPT',
    WRAP: 'WRAP',
    AGREE: 'AGREE',
    //ATTEST: 'ATTEST' // NOTE: ATTEST has been removed to keep the API symmetric between platforms
} as const;

const keyPurposeSet: ReadonlySet<keyof typeof keyPurposes> = new Set(Object.values(keyPurposes));

export const isKeyPurpose = createInSetGuard(keyPurposeSet);

export const keyPurposeFamilies = {
    SIGN: 0, 
    VERIFY: 0,
    ENCRYPT: 1,
    DECRYPT: 1,
    WRAP: 2,
    AGREE: 3,
    //ATTEST: 4 // NOTE: ATTEST has been removed to keep the API symmetric between platforms
}

// Digests
export const keyDigests = {
    SHA256: 'SHA256',
    SHA384: 'SHA384',
    SHA512: 'SHA512'
} as const;

const keyDigestSet: ReadonlySet<keyof typeof keyDigests> = new Set(Object.values(keyDigests));

export const isKeyDigest = createInSetGuard(keyDigestSet);

// RSA Paddings
export const signaturePaddingAlgorithms = {
    PKCS1: 'PKCS1',
    PSS: 'PSS'
} as const;

const signaturePaddingAlgorithmsSet: ReadonlySet<keyof typeof signaturePaddingAlgorithms> = new Set(Object.values(signaturePaddingAlgorithms));

export const isSignaturePaddingAlgorithm = createInSetGuard(signaturePaddingAlgorithmsSet);

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
    B64: 'B64',
    B64URL: 'B64URL',
    SPKI: 'SPKI'
} as const;

const pubkeyFormatSet: ReadonlySet<keyof typeof pubkeyFormats> = new Set(Object.values(pubkeyFormats));

export const isPubkeyFormat = createInSetGuard(pubkeyFormatSet);

// Android algorithms
export const androidAlgorithms = {
    EC_P256: 'EC_P256'
    /*
    EC_P384: 'EC_P384',
    EC_P521: 'EC_P521',
    RSA_2048: 'RSA_2048', 
    RSA_3072: 'RSA_3072',
    RSA_4096: 'RSA_4096',
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
    //PREFER_STRONGBOX_ALLOW_SOFTWARE: 'PREFER_STRONGBOX_ALLOW_SOFTWARE',
    REQUIRE_TEE: 'REQUIRE_TEE',
    //PREFER_TEE_ALLOW_SOFTWARE: 'PREFER_TEE_ALLOW_SOFTWARE',
    //SOFTWARE_ONLY: 'SOFTWARE_ONLY'
} as const;

const androidHardwarePolicySet: ReadonlySet<keyof typeof androidHardwarePolicies> = new Set(Object.values(androidHardwarePolicies));

export const isAndroidHardwarePolicy = createInSetGuard(androidHardwarePolicySet);

// iOS algorithms
export const iosAlgorithms = {
    EC_P256: 'EC_P256',
    EC_P384: 'EC_P384',
    EC_P521: 'EC_P521',
    RSA_2048: 'RSA_2048', 
    RSA_3072: 'RSA_3072',
    RSA_4096: 'RSA_4096'
} as const;

const iosAlgorithmSet: ReadonlySet<keyof typeof iosAlgorithms> = new Set(Object.values(iosAlgorithms));

export const isIosAlgorithm = createInSetGuard(iosAlgorithmSet);

// iOS hardware policies
export const iosHardwarePolicies = {
    REQUIRE_SECURE_ENCLAVE: 'REQUIRE_SECURE_ENCLAVE',
    PREFER_SECURE_ENCLAVE: 'PREFER_SECURE_ENCLAVE',
    SOFTWARE_ONLY: 'SOFTWARE_ONLY'
} as const;

const iosHardwarePolicySet: ReadonlySet<keyof typeof iosHardwarePolicies> = new Set(Object.values(iosHardwarePolicies));

export const isIosHardwarePolicy = createInSetGuard(iosHardwarePolicySet);
