
export interface Capabilities {
    /**
     * String representing the available hardware capabilities.
     * * ANDROID_STRONGBOX - The device is an android device with StrongBox support
     * * ANDROID_TEE - The device is an android device with TEE support only
     * * IOS_SECURE_ENCLAVE - The device is an iOS device with secure enclave support
     * * SOFTWARE - The device is not capable of hardware-backed cryptography
     *  and can only use software crypto
     */
    securityLevel: "ANDROID_STRONGBOX" | "ANDROID_TEE" | "IOS_SECURE_ENCLAVE" | "SOFTWARE",
    
    /**
     * String representing the user authentication capabilities.
     * * BIOMETRICS_STRONG - The device has strong biometrics hardware and the user has it enabled.
     * * BIOMETRICS_WEAK - The device has weak biometrics hardware and the user has it enabled.
     * * DEVICE_CREDENTIAL - The device does not have biometrics hardware or the user has it disabled. But the device still 
     * has standard authentication methods i.e., the device is protected with a PIN, pattern, or password.
     * * NONE - The device is not protected with any form of authentication.
     * @note IOS devices that have biometrics enabled will always be BIOMETRICS_STRONG and never BIOMETRICS_WEAK.
     */
    userAuthLevel: "BIOMETRICS_STRONG" | "BIOMETRICS_WEAK" | "DEVICE_CREDENTIAL" | "NONE",

    /**
     * true if the device is capable of key attestation
     */
    canAttest: boolean
};
