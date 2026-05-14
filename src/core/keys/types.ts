export type KeyPurpose = 'SIGN' | 'VERIFY' | 'ENCRYPT' | 'DECRYPT' | 'WRAP' | 'AGREE' | 'ATTEST';
type KeyDigests = 'SHA256'

/**
 * Note: We currently only support Asymmetric ES256. Other algorithms will be added soon.
 */ 
export interface GenerateKeyOpts {
    /**
     * set of purposes (e.g., encrypt, decrypt, sign) for which the key can be used. 
     * Attempts to use the key for any other purpose will be rejected.
     * 
     * @default 'SIGN' and 'VERIFY'
     */
    purposes?: KeyPurpose[];
    
    /**
     * User Authentication options for the key
     */
    userAuth?: {
        /**
         * Requires user auth to use the key
         * 
         * @default false
         */
        require: boolean;

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
        timeout: number;

        /**
         * Invalidates the key if new Biometrics are added to the device.
         * 
         * @default true
         */
        invalidateOnEnrollment: boolean;

        /**
         * * BIOMETRICS_ONLY - Only allows Biometric authentication 
         * * BIOMETRICS_OR_CREDENTIAL - Allows either Biometric authentication or non-biometric credential used to secure the device (i.e., PIN, pattern, or password)
         * 
         * Works flawlessly on Android 11+ and iOS. On Android 10 and below, it safely degrades to standard per-use biometric authentication governed by the older OS's standard system prompt behavior.
         * 
         * @default BIOMETRICS_ONLY
         */
        policy: 'BIOMETRICS_ONLY' | 'BIOMETRICS_OR_CREDENTIAL';
    };

    /**
     * IMPORTANT: You cannot attest an existing key after the fact.
     * 
     * Optional attest challenge string.
     * 
     * If provided, you will be able to call 'attestKey'
     * to get the PEM certificate.
     */
    attestChallenge?: string;

    /**
     * Format for the returned public key.
     * * PEM - Base64 encoded string with PEM header and footer
     * * B64 - Base64 encoded string
     * 
     * @default PEM
     */
    pubkeyFormat?: 'PEM' | 'B64';

    /**
     * Android specific options
     */
    android?: {
        /**
         * The key algorithm
         * 
         * @default ES256
         */
        algorithm: 'ES256';
        
        /**
         * Sets the set of digests algorithms (e.g., SHA-256, SHA-384) with which the key can be used. 
         * Attempts to use the key with any other digest algorithm will be rejected.
         * 
         * For HMAC keys, the default is the digest associated with the key algorithm (e.g., SHA-256 for key algorithm HmacSHA256). 
         * HMAC keys cannot be authorized for more than one digest.
         * 
         * @default SHA256
         */
        digests: KeyDigests[];

        /**
         * The policy to use when creating the key.
         * * requireStrongbox - Will fail the key generation if StrongBox is not available on the device
         * * preferStrongbox - Will attempt to store the key in StrongBox and fall back to TEE if strongbox is not available on the device
         * * useTEE - Will not attempt to use StrongBox and will use TEE
         * 
         * @default PREFER_STRONGBOX
         */
        hardwarePolicy: 'REQUIRE_STRONGBOX' | 'PREFER_STRONGBOX' | 'USE_TEE';
    };

    /**
     * IOS specific options
     */
    ios?: {
        algorithm: 'ES256';
        hardwarePolicy: 'require' | 'prefer' | 'software';
    };
};

/**
 * KeyInfo object returned by getKeyInfo
 */
export interface KeyInfo {
    /**
     * The alias of the key
     */
    alias: string;

    /**
     * The key algorithm
     */
    algorithm: string;

    /**
     * Size of the key in bits
     */
    keySize: number;

    /**
     * The set of digest algorithms (e.g., SHA-256, SHA-384) with which the key can be used
     */
    digests: string[];

    /**
     * Security level of the key (where it is stored)
     */
    securityLevel: 'STRONGBOX' | 'TEE' | 'SOFTWARE';
    
    /**
     * Array of purposes for which the key can be used
     */
    purposes: KeyPurpose[];

    /**
     * True if user auth is required to use the key
     */
    isUserAuthRequired: boolean;

    /**
     * True if the key will be invalidated if new biometrics
     * are added on the device
     */
    isInvalidatedByBiometricEnrollment: boolean;

    /**
     * The amount of time (in seconds) that the key can be used
     * for after the user has successfully authenticated
     */
    userAuthValidityDurationSecs: number;
}
