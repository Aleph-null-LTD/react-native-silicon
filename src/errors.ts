import { hasOwn } from "./utils/validation";

type SiliconErrorOpts = {
    cause?: unknown
    nativeStack?: string | null
}

export enum SiliconErrorCode {
    /**
     * Occurs when generateKey failed for an unknown reason
     */
    KEY_GENERATION_FAILED = 'KEY_GENERATION_FAILED',
    
    /**
     * Occurs when getCapabilities failed for an unknown reason
     */
    GET_CAPABILITIES_FAILED = 'GET_CAPABILITIES_FAILED',

    /**
     * Occurs when getPubKey failed for an unknown reason
     */
    GET_PUB_KEY_FAILED = 'GET_PUB_KEY_FAILED',
    
    /**
     * Occurs when getKeyInfo failed for an unknown reason
     */
    GET_KEY_INFO_FAILED = 'GET_KEY_INFO_FAILED',
    
    /**
     * Occurs when validateKey failed for an unknown reason
     */
    KEY_VALIDATION_FAILED = 'KEY_VALIDATION_FAILED',
    
    /**
     * Occurs when verify failed for an unknown reason
     */
    VERIFICATION_FAILED = 'VERIFICATION_FAILED',
    
    /**
     * Occurs when generateSecureRandomBytes failed for an unknown reason
     */
    RANDOM_GEN_FAILED = 'RANDOM_GEN_FAILED',
    
    /**
     * Occurs when getJwk failed for an unknown reason
     */
    GET_JWK_FAILED = 'GET_JWK_FAILED',

    /**
     * Occurs when sign failed for an unknown reason
     * @note some abstractions that use 'sign' under the hood (e.g., signJwt) can also throw this error
     */
    SIGNING_FAILED = 'SIGNING_FAILED',

    /**
     * Occurs when deleteKey failed for an unknown reason
     */
    DELETE_FAILED = 'DELETE_FAILED',
    
    /**
     * Occurs when deleteAllKeys failed for an unknown reason
     */
    BULK_DELETE_FAILED = 'BULK_DELETE_FAILED',
    
    /**
     * Occurs when keyExists failed for an unknown reason
     */
    KEY_EXISTS_FAILED = 'KEY_EXISTS_FAILED',
    
    /**
     * Occurs when listKeys failed for an unknown reason
     */
    KEY_LIST_FAILED = 'KEY_LIST_FAILED',
    
    /**
     * Occurs when attestKey failed for an unknown reason
     */
    ATTEST_FAILED = 'ATTEST_FAILED',

    PLATFORM_NOT_SUPPORTED = 'PLATFORM_NOT_SUPPORTED',
    
    INVALID_ALGORITHM_PARAMETER = 'INVALID_ALGORITHM_PARAMETER',
    
    /**
     * Occurs if the generateKey policy was set to 'STRONGBOX_ONLY'
     * but the device does not support StrongBox
     */
    STRONGBOX_NOT_SUPPORTED = 'STRONGBOX_NOT_SUPPORTED',
    
    /**
     * Occurs when 'WRAP' is present in the purpose array when calling generateKey
     * but the device does not support it
     */
    PURPOSE_WRAP_NOT_SUPPORTED = 'PURPOSE_WRAP_NOT_SUPPORTED',
    
    /**
     * Occurs when 'AGREE' is present in the purpose array when calling generateKey
     * but the device does not support it
     */
    PURPOSE_AGREE_NOT_SUPPORTED = 'PURPOSE_AGREE_NOT_SUPPORTED',
    
    /**
     * Occurs when a key with the specified alias cannot be found
     */
    KEY_NOT_FOUND = 'KEY_NOT_FOUND',
    
    /**
     * Occurs when a key with the specified alias was found,
     * but the key could not be loaded
     */
    KEY_LOAD_FAILED = 'KEY_LOAD_FAILED',
    
    /**
     * Occurs when an operation is attempted with a key, but the key has been invalidated 
     * e.g., New biometrics were enrolled and the invalidateOnEnrollment was set to true when the key was generated
     */
    KEY_INVALIDATED = 'KEY_INVALIDATED',
    
    /**
     * Occurs when an operation is attempted with a key that is incompatible
     * with said operation
     */
    UNSUPPORTED_KEY_FAMILY = 'UNSUPPORTED_KEY_FAMILY',
    
    HARDWARE_NOT_AVAILABLE = 'HARDWARE_NOT_AVAILABLE',

    BIOMETRICS_NOT_ENROLLED = 'BIOMETRICS_NOT_ENROLLED',
    
    INVALID_SIGNATURE = 'INVALID_SIGNATURE',
    
    /**
     * Occurs when attestKey is called for a key that did not have 
     * an attest challenge supplied when it was generated
     */
    NO_ATTEST_CHALLENGE = 'NO_ATTEST_CHALLENGE',
    
    
    NO_CERT_CHAIN = 'NO_CERT_CHAIN',
    
    NO_CERT = 'NO_CERT',
    
    /**
     * Occurs when the alias is already used for another key
     */
    ALIAS_IN_USE = 'ALIAS_IN_USE',
    
    /**
     * Occurs if the key cannot be used for any reason
     */
    INVALID_KEY = 'INVALID_KEY',
    
    /**
     * User authentication was cancelled by the user or system
     */
    AUTH_CANCELED = 'AUTH_CANCELED' ,
    
    /**
     * User authentication was cancelled due to too many attempts 
     * and the user is locked out temporarily
     */
    AUTH_LOCKED_OUT = 'AUTH_LOCKED_OUT',
    
    /**
     * User authentication failed because biometrics is not enrolled on the device
     */
    AUTH_NOT_ENROLLED = 'AUTH_NOT_ENROLLED',
    
    /**
     * User authentication failed due to a system error
     */
    AUTH_SYSTEM_ERROR = 'AUTH_SYSTEM_ERROR',
    
    /**
     * An unknown native error was thrown
     * @note These should be reported to the react-native-silicon team
     */
    UNKNOWN_NATIVE_ERROR = 'UNKNOWN_NATIVE_ERROR',
};

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
