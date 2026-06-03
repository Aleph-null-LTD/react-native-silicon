import { androidAlgorithms, androidHardwarePolicies, iosAlgorithms, iosHardwarePolicies, keyDigests, keyPurposes, pubkeyFormats, signaturePaddingAlgorithms, userAuthPolicies } from "./constants";

type KeyDigests = keyof typeof keyDigests;
type UserAuthPolicies = keyof typeof userAuthPolicies;
type PubkeyFormat = keyof typeof pubkeyFormats;
type SignaturePaddingAlgorithms = keyof typeof signaturePaddingAlgorithms;

type AndroidAlgorithm = keyof typeof androidAlgorithms;
type AndroidHardwarePolicy = keyof typeof androidHardwarePolicies;

type IosAlgorithm = keyof typeof iosAlgorithms;
type IosHardwarePolicy = keyof typeof iosHardwarePolicies;

/**
 * Note: We currently only support Asymmetric ES256. Other algorithms will be added soon.
 */ 
export type GenerateKeyOpts = {
    /**
     * set of purposes (e.g., encrypt, decrypt, sign) for which the key can be used. 
     * Attempts to use the key for any other purpose will be rejected.
     * 
     * Most purposes are mutually exclusive for security reasons 
     * e.g., a key that has the purpose "SIGN" cannot also have the "ENCRYPT" purpose etc.
     *
     * When purpose "SIGN" is present, the key will automatically inherit the "VERIFY" purpose and vice versa.
     * When "ENCRYPT" is present, the key will automatically inherit the "DECRYPT" purpose and vice versa.
     * 
     * @note Keys generated in the iOS Secure Enclave will always have the SIGN and AGREE purposes. 
     * Regardless of what you passed in (this is enforced at the hardware level). 
     * Setting ENCRYPT/DECRYPT will prepare the key to be used for ECIES encryption but iOS will not enforce that 
     * it can only be used for encryption. It is recommended that you do NOT use a key for both signing and encryption, 
     * as it is considered a major architectural flaw and security vulnrebility. 
     * The same can be said about using a single key for both SIGN and AGREE (even though the Secure Enclave technically allows it we strongly recommend that you do NOT).
     * 
     * @default 
     * ["SIGN", "VERIFY"]
     */
    purposes?: (typeof keyPurposes.SIGN | typeof keyPurposes.VERIFY)[] |
        (typeof keyPurposes.ENCRYPT | typeof keyPurposes.DECRYPT)[] |
        [typeof keyPurposes.AGREE] |
        [typeof keyPurposes.WRAP] |
        //[typeof keyPurposes.ATTEST] | // NOTE: ATTEST has been removed to keep the API symmetric between platforms
        undefined,
    
    /**
     * User Authentication options for the key
     */
    userAuth?: {
        /**
         * Requires user auth to use the key.
         * 
         * @default false
         * @note If this is false then the rest of the userAuth options will do nothing.
         */
        require?: boolean | undefined,

        /**
         * Int value. MUST be >=0 AND <=6000
         * 
         * Sets the duration of time (seconds) and authorization type for which this key is authorized 
         * to be used after the user is successfully authenticated.
         * 
         * set 0 if user authentication must take place for every use of the key.
         * 
         * @default 0
         */
        timeout?: number | undefined,

        /**
         * Invalidates the key if new Biometrics are added to the device.
         * 
         * @default true
         */
        invalidateOnEnrollment?: boolean | undefined,

        /**
         * * BIOMETRICS_ONLY - Only allows Biometric authentication 
         * * BIOMETRICS_OR_CREDENTIAL - Allows either Biometric authentication or non-biometric credential used to secure the device (i.e., PIN, pattern, or password)
         * 
         * Works flawlessly on Android 11+ and iOS. On Android 10 and below, it safely degrades to standard per-use biometric authentication governed by the older OS's standard system prompt behavior.
         * 
         * @default BIOMETRICS_ONLY
         */
        policy?: UserAuthPolicies | undefined
    } | undefined,

    /**
     * IMPORTANT: You cannot attest an existing key after the fact.
     * 
     * Optional attest challenge string.
     * 
     * If provided, you will be able to call 'attestKey'
     * to get the PEM certificate.
     */
    attestChallenge?: string | undefined,

    /**
     * Format for the returned public key.
     * * PEM - Base64 encoded string with PEM header and footer
     * * B64 - Base64 encoded string
     * 
     * @default PEM
     */
    pubkeyFormat?: PubkeyFormat | undefined,

    /**
     * Android specific options
     */
    android?: {
        /**
         * The key algorithm
         * 
         * @default EC_P256
         */
        algorithm?: AndroidAlgorithm | undefined,
        
        /**
         * The set of digests algorithms (e.g., SHA-256, SHA-384) with which the key can be used. 
         * Attempts to use the key with any other digest algorithm will be rejected.
         * 
         * **Default:** Matches the size of the key algorithm (e.g., "SHA256" for "EC_P256").
         * 
         * @note For HMAC keys, the default is the digest associated with the key algorithm (e.g., SHA-256 for key algorithm HmacSHA256). 
         * HMAC keys cannot be authorized for more than one digest.
         */
        digests?: KeyDigests[] | undefined,

        /**
         * The signature padding algorithm to use for RSA keys when signing and verifying.
         * 
         * **Default:** "PSS" for RSA keys with SIGN/VERIFY purpose, else undefined
         * 
         * @note Only used for RSA keys with the SIGN/VERIFY purpose and is ignored for everything else
         */
        signaturePaddingAlgorithm?: SignaturePaddingAlgorithms,

        /**
         * The policy to use when creating the key.
         * * REQUIRE_STRONBOX - Will fail the key generation if StrongBox is not available on the device
         * * PREFER_STRONGBOX - Will attempt to store the key in StrongBox and fall back to TEE if strongbox is not available on the device 
         * (Fails if neither are available).
         * * PREFER_STRONGBOX_ALLOW_SOFTWARE - Will attempt to store the key in StrongBox and fall back to TEE if strongbox is not available then fallback to 
         * software if TEE is not available
         * * REQUIRE_TEE - Will not attempt to use TEE and fails if TEE is not available
         * * PREFER_TEE_ALLOW_SOFTWARE - Will not attempt to use TEE and will fallback to software if unavailable
         * * SOFTWARE_ONLY - Will create a software key (not hardware-backed)
         * 
         * @default 'PREFER_STRONGBOX'
         */
        hardwarePolicy?: AndroidHardwarePolicy | undefined
    } | undefined,

    /**
     * IOS specific options
     */
    ios?: {
        /**
         * The key algorithm
         * 
         * @default EC_P256
         */
        algorithm?: IosAlgorithm | undefined,

        /**
         * The set of digests algorithms (e.g., SHA-256, SHA-384) with which the key can be used. 
         * Attempts to use the key with any other digest algorithm will be rejected.
         * 
         * **Default:** Matches the size of the key algorithm (e.g., "SHA256" for "EC_P256").
         * 
         * @note For HMAC keys, the default is the digest associated with the key algorithm (e.g., SHA-256 for key algorithm HmacSHA256). 
         * HMAC keys cannot be authorized for more than one digest.
         */
        digests?: KeyDigests[] | undefined,

        /**
         * The signature padding algorithm to use for RSA keys when signing and verifying.
         * 
         * **Default:** "PSS" for RSA keys with SIGN/VERIFY purpose, else undefined
         * 
         * @note Only used for RSA keys with the SIGN/VERIFY purpose and is ignored for everything else
         */
        signaturePaddingAlgorithm?: SignaturePaddingAlgorithms,

        /**
         * The policy to use when creating the key.
         * * REQUIRE_SECURE_ENCLAVE - Will fail the key generation if Secure Enclave is not available on the device
         * * PREFER_SECURE_ENCLAVE - Will attempt to store the key in Secure Enclave and fall back to software if Secure Enclave is not available on the device
         * * SOFTWARE_ONLY - Will generate a software key (Not hardware-backed)
         * 
         * @default 'REQUIRE_SECURE_ENCLAVE'
         */
        hardwarePolicy?: IosHardwarePolicy | undefined
    } | undefined,
};

/**
 * KeyInfo object returned by getKeyInfo
 */
export type KeyInfo = {
    /**
     * The alias of the key
     */
    alias: string,

    /**
     * The key algorithm - EC, RS, etc.
     */
    algorithm: string,

    /**
     * The curve 
     * @note Only included if the key algorithm is Eliptic Curve (EC)
     */
    curve?: string,

    /**
     * Size of the key in bits
     */
    keySize: number,

    /**
     * The set of digest algorithms (e.g., SHA-256, SHA-384) with which the key can be used
     * @note This is unavailable on iOS
     */
    digests?: string[],

    /**
     * Security level of the key (where it is stored)
     */
    securityLevel: 'STRONGBOX' | 'TEE' | 'SECURE_ENCLAVE' | 'SOFTWARE',
    
    /**
     * Array of purposes for which the key can be used
     * @note Keys generated in the iOS Secure Enclave will always have the SIGN and AGREE purposes. 
     * Regardless of what you passed in to generateKey (this is enforced at the hardware level).
     */
    purposes: (keyof typeof keyPurposes)[],

    /**
     * True if user auth is required to use the key
     */
    isUserAuthRequired: boolean,

    /**
     * True if the key will be invalidated if new biometrics
     * are added on the device
     * @note This is Android only
     */
    isInvalidatedByBiometricEnrollment?: boolean,

    /**
     * The amount of time (in seconds) that the key can be used
     * for after the user has successfully authenticated
     * @note this will not be present if it is not enabled.
     */
    userAuthValidityDurationSecs?: number,

    /**
     * The raw string value of the iOS kSecAttrAccessible key attribute.
     * * kSecAttrAccessibleWhenUnlocked - "ak"
     * * kSecAttrAccessibleAfterFirstUnlock - "ck"
     * * kSecAttrAccessibleAlways (Deprecated) - "dk"
     * * kSecAttrAccessibleWhenUnlockedThisDeviceOnly - "aku"
     * * kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly - "cku"
     * * kSecAttrAccessibleAlwaysThisDeviceOnly (Deprecated) - "dku"
     * * kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly - "akpu"
     * 
     * see https://developer.apple.com/documentation/security/ksecattraccessible
     * @note This is iOS only
     */
    accessibleClass?: string
};

/**
 * The result returned when performing an attest on an Android device
 */
type AndroidAttestResult = {
    platform: 'ANDROID',
    
    /**
     * An array of Base64-encoded X.509 certificates.
     * Index 0 is the leaf certificate containing the attestation extension.
     */
    certChain: string[]
};

/**
 * The result returned when performing an attest on an iOS device
 */
type IosAttestResult = {
    platform: 'IOS',
  
    /**
     * 
     */
    signingPubKey: string,

    /**
     * A Base64-encoded CBOR attestation object containing the 
     * 'x5c' certificate chain and the Apple authenticator data.
     */
    attestationObject: string
};

/**
 * The result returned when performing an attest
 */
export type AttestResult = AndroidAttestResult | IosAttestResult;
