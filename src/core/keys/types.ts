import { androidAlgorithms, androidHardwarePolicies, iosAlgorithms, iosHardwarePolicies, keyDigests, keyPurposes, pubkeyFormats, userAuthPolicies } from "./constants";

type KeyDigests = keyof typeof keyDigests;
type UserAuthPolicies = keyof typeof userAuthPolicies;
type PubkeyFormat = keyof typeof pubkeyFormats;

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
     * @note Most purposes are mutually exclusive for security reasons 
     * e.g., a key that has the purpose "SIGN" cannot also have the "ENCRYPT" purpose etc.
     * @default ["SIGN", "VERIFY"]
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
         * Int value.
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
         * @default ES256
         */
        algorithm?: AndroidAlgorithm | undefined,
        
        /**
         * Sets the set of digests algorithms (e.g., SHA-256, SHA-384) with which the key can be used. 
         * Attempts to use the key with any other digest algorithm will be rejected.
         * 
         * **Default:** Matches the size of the key algorithm (e.g., "SHA256" for "ES256").
         * 
         * @note For HMAC keys, the default is the digest associated with the key algorithm (e.g., SHA-256 for key algorithm HmacSHA256). 
         * HMAC keys cannot be authorized for more than one digest.
         */
        digests?: KeyDigests[] | undefined,

        /**
         * The policy to use when creating the key.
         * * REQUIRE_STRONBOX - Will fail the key generation if StrongBox is not available on the device
         * * PREFER_STRONGBOX - Will attempt to store the key in StrongBox and fall back to TEE if strongbox is not available on the device
         * * USE_TEE - Will not attempt to use StrongBox and will use TEE
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
         * @default ES256
         */
        algorithm?: IosAlgorithm | undefined,

        /**
         * The policy to use when creating the key.
         * * REQUIRE_SECURE_ENCLAVE - Will fail the key generation if Secure Enclave is not available on the device
         * * PREFER_SECURE_ENCLAVE - Will attempt to store the key in Secure Enclave and fall back to TEE if strongbox is not available on the device
         * * SOFTWARE_ONLY - Will not attempt to use StrongBox and will use TEE
         * 
         * @default 'PREFER_SECURE_ENCLAVE'
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
     * The key algorithm
     */
    algorithm: string,

    /**
     * The curve 
     * @note Only included if the key is an Eliptic Curve
     */
    curve?: string,

    /**
     * Size of the key in bits
     */
    keySize: number,

    /**
     * The set of digest algorithms (e.g., SHA-256, SHA-384) with which the key can be used
     */
    digests: string[],

    /**
     * Security level of the key (where it is stored)
     */
    securityLevel: 'STRONGBOX' | 'TEE' | 'SOFTWARE',
    
    /**
     * Array of purposes for which the key can be used
     */
    purposes: (keyof typeof keyPurposes)[],

    /**
     * True if user auth is required to use the key
     */
    isUserAuthRequired: boolean,

    /**
     * True if the key will be invalidated if new biometrics
     * are added on the device
     */
    isInvalidatedByBiometricEnrollment: boolean,

    /**
     * The amount of time (in seconds) that the key can be used
     * for after the user has successfully authenticated
     */
    userAuthValidityDurationSecs: number
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
