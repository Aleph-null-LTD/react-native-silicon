import { hasOwn } from "./utils/validation";

type SiliconErrorOpts = {
    cause?: unknown,
    nativeStack?: string | null
}

export enum SiliconErrorCode {
    /**
     * Occurs when the alias is already used for another key
     */
    ALIAS_IN_USE = 'ALIAS_IN_USE',

    /**
     * Occurs when attestKey failed
     */
    ATTEST_KEY_FAILED = 'ATTEST_KEY_FAILED',

    /**
     * Attestation is not available on the device
     */
    ATTEST_NOT_AVAILABLE = 'ATTEST_NOT_AVAILABLE',

    /**
     * User authentication was cancelled by the user or system
     */
    AUTH_CANCELED = 'AUTH_CANCELED' ,

    /**
     * User authentication failed
     */
    AUTH_FAILED = 'AUTH_FAILED',
    
    /**
     * User authentication was cancelled due to too many attempts 
     * and the user is locked out temporarily
     */
    AUTH_LOCKED_OUT = 'AUTH_LOCKED_OUT',

    /**
     * Biometrics hardware is not available on the device
     */
    BIOMETRICS_NOT_AVAILABLE = 'BIOMETRICS_NOT_AVAILABLE',

    /**
     * User has not enrolled biometrics on the device
     */
    BIOMETRICS_NOT_ENROLLED = 'BIOMETRICS_NOT_ENROLLED',

    /**
     * Occurs when deleteAllKeys failed
     */
    DELETE_ALL_FAILED = 'DELETE_ALL_FAILED',

    /**
     * Occurs when deleteKey failed
     */
    DELETE_FAILED = 'DELETE_FAILED',
    
    /**
     * Device is not protected by PIN/passcode/pattern
     */
    DEVICE_NOT_SECURE = 'DEVICE_NOT_SECURE',
    
    /**
     * Occurs when generateKey failed
     */
    GENERATE_KEY_FAILED = 'GENERATE_KEY_FAILED',
    
    /**
     * Occurs when getCapabilities failed
     */
    GET_CAPABILITIES_FAILED = 'GET_CAPABILITIES_FAILED',

    /**
     * Occurs when getJwk failed
     */
    GET_JWK_FAILED = 'GET_JWK_FAILED',

    /**
     * Occurs when getKeyInfo failed
     */
    GET_KEY_INFO_FAILED = 'GET_KEY_INFO_FAILED',
    
    /**
     * Occurs when getPubKey failed
     */
    GET_PUB_KEY_FAILED = 'GET_PUB_KEY_FAILED',
    
    /**
     * Hardware-backed crypto is not available on the device
     */
    HARDWARE_NOT_AVAILABLE = 'HARDWARE_NOT_AVAILABLE',

    /**
     * Occurs when a function cannot complete because something is
     * fundamentally incompatible
     */
    INCOMPATIBLE = 'INCOMPATIBLE',

    /**
     * Internal library errors
     * @note Report these to the react-native-silicon team
     */
    INTERNAL_ERROR = 'INTERNAL_ERROR',

    /**
     * Occurs when an invalid argument was passed
     */
    INVALID_ARGUMENT = 'INVALID_ARGUMENT',
    
    /**
     * Occurs when keyExists failed
     */
    KEY_EXISTS_FAILED = 'KEY_EXISTS_FAILED',

    /**
     * Occurs when an operation is attempted with a key, but the key has been invalidated 
     * e.g., New biometrics were enrolled and the invalidateOnEnrollment was set to true when the key was generated
     */
    KEY_INVALIDATED = 'KEY_INVALIDATED',
    
    /**
     * Occurs when a key with the specified alias cannot be found
     */
    KEY_NOT_FOUND = 'KEY_NOT_FOUND',
    
    /**
     * Occurs when a function cannot complete because something violated the key's restrictions (policies)
     */
    KEY_POLICY_VIOLATION = 'KEY_POLICY_VIOLATION',
    
    /**
     * Occurs when listKeys failed
     */
    LIST_KEYS_FAILED = 'LIST_KEYS_FAILED',
    
    /**
     * Malformed data was detected
     */
    MALFORMED_DATA = 'MALFORMED_DATA',
    
    /**
     * An operation cannot be performed due to a limitation
     */
    OPERATION_NOT_PERMITTED = 'OPERATION_NOT_PERMITTED',
    
    /**
     * Current platform is not supported (i.e., web)
     */
    PLATFORM_NOT_SUPPORTED = 'PLATFORM_NOT_SUPPORTED',
    
    /**
     * Occurs when 'AGREE' is present in the purpose array when calling generateKey
     * but the device does not support it
     */
    PURPOSE_AGREE_NOT_SUPPORTED = 'PURPOSE_AGREE_NOT_SUPPORTED',
    
    /**
     * Occurs when 'WRAP' is present in the purpose array when calling generateKey
     * but the device does not support it
     */
    PURPOSE_WRAP_NOT_SUPPORTED = 'PURPOSE_WRAP_NOT_SUPPORTED',
    
    /**
     * Occurs when generateSecureRandomBytes failed
     */
    RANDOM_GEN_FAILED = 'RANDOM_GEN_FAILED',
    
    /**
     * Occurs when sign failed
     * @note some abstractions that use 'sign' under the hood (e.g., signJwt) can also throw this error
     */
    SIGN_FAILED = 'SIGN_FAILED',

    /**
     * Occurs if the generateKey policy was set to 'STRONGBOX_ONLY'
     * but the device does not support StrongBox
     */
    STRONGBOX_NOT_SUPPORTED = 'STRONGBOX_NOT_SUPPORTED',
    
    /**
     * An unknown native error was thrown
     * @note This should be reported to the react-native-silicon team
     */
    UNKNOWN_NATIVE_ERROR = 'UNKNOWN_NATIVE_ERROR',

    /**
     * Unsupported features
     */
    UNSUPPORTED = 'UNSUPPORTED',
    
    /**
     * Occurs when validateKey failed
     */
    VALIDATE_KEY_FAILED = 'VALIDATE_KEY_FAILED',
    
    /**
     * Occurs when verify failed
     */
    VERIFY_FAILED = 'VERIFY_FAILED'
}

export class SiliconError extends Error {
    readonly code: SiliconErrorCode;
    readonly nativeStack?: string;

    constructor(code: SiliconErrorCode, message: string, opts?: SiliconErrorOpts) {
        super(message);
        this.name = 'SiliconError';
        this.code = code;
        this.cause = opts?.cause;
        this.nativeStack = opts?.nativeStack || undefined

        // Maintain stack trace (If supported)
        if (hasOwn(Error, 'captureStackTrace')) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (Error as any).captureStackTrace(this, SiliconError);
        }
    }

    /**
     * Converts the error into a POJO
     * @note 'cause' will be recursively extracted
     * @returns 
     */
    public toJSON(): Record<string, unknown> {
        const extractCause = (cause: unknown): unknown => {
            if (cause instanceof SiliconError) {
                return {
                    name: cause.name,
                    code: cause.code,
                    message: cause.message,
                    stack: cause.stack,
                    nativeStack: cause.nativeStack,
                    cause: hasOwn(cause, 'cause') ? extractCause(cause.cause) : undefined
                }

            } else if (cause instanceof Error) {
                const extractedErr = {
                    name: cause.name,
                    message: cause.message,
                    stack: cause.stack,
                    cause: hasOwn(cause, 'cause') ? extractCause(cause.cause) : undefined
                }
                return extractedErr;

            } else {
                return cause;

            }
        };
        
        return {
            name: this.name,
            code: this.code,
            message: this.message,
            stack: this.stack,
            nativeStack: this.nativeStack,
            cause: this.cause ? extractCause(this.cause) : undefined
        }
    }

    /**
     * Serializes the error into a JSON string
     * @param space maps directly to the 'space' parameter on JSON.stringify()
     * @returns 
     */
    public serialize(space?: string | number | undefined): string {
        return JSON.stringify(this.toJSON(), undefined, space);
    }
}
