import { hasOwn } from "./utils/validation";

type SiliconErrorOpts = {
    cause?: unknown
    nativeStack?: string | null
}

export enum SiliconErrorCode {
    GET_CAPABILITIES_FAILED = 'GET_CAPABILITIES_FAILED',
    PLATFORM_NOT_SUPPORTED = 'PLATFORM_NOT_SUPPORTED',
    INVALID_ALGORITHM_PARAMETER = 'INVALID_ALGORITHM_PARAMETER',
    STRONGBOX_NOT_SUPPORTED = 'STRONGBOX_NOT_SUPPORTED',
    PURPOSE_WRAP_NOT_SUPPORTED = 'PURPOSE_WRAP_NOT_SUPPORTED',
    PURPOSE_AGREE_NOT_SUPPORTED = 'PURPOSE_AGREE_NOT_SUPPORTED',
    KEY_NOT_FOUND = 'KEY_NOT_FOUND',
    KEY_LOAD_FAILED = 'KEY_LOAD_FAILED',
    KEY_INVALIDATED = 'KEY_INVALIDATED',
    UNSUPPORTED_KEY_FAMILY = 'UNSUPPORTED_KEY_FAMILY',
    SIGNING_FAILED = 'SIGNING_FAILED',
    HARDWARE_NOT_AVAILABLE = 'HARDWARE_NOT_AVAILABLE',
    BIOMETRICS_NOT_ENROLLED = 'BIOMETRICS_NOT_ENROLLED',
    USER_CANCELLED = 'USER_CANCELLED',
    INVALID_SIGNATURE = 'INVALID_SIGNATURE',
    DELETE_FAILED = 'DELETE_FAILED',
    BULK_DELETE_FAILED = 'BULK_DELETE_FAILED',
    KEY_CHECK_FAILED = 'KEY_CHECK_FAILED',
    KEY_LIST_FAILED = 'KEY_LIST_FAILED',
    NO_ATTEST_CHALLENGE = 'NO_ATTEST_CHALLENGE',
    ATTEST_FAILED = 'ATTEST_FAILED',
    NO_CERT_CHAIN = 'NO_CERT_CHAIN',
    NO_CERT = 'NO_CERT',
    GET_PUB_KEY_FAILED = 'GET_PUB_KEY_FAILED',
    GET_KEY_INFO_FAILED = 'GET_KEY_INFO_FAILED',
    KEY_VALIDATION_FAILED = 'KEY_VALIDATION_FAILED',
    VERIFICATION_FAILED = 'VERIFICATION_FAILED',
    RANDOM_GEN_FAILED = 'RANDOM_GEN_FAILED',
    GET_JWK_FAILED = 'GET_JWK_FAILED',
    ALIAS_IN_USE = 'ALIAS_IN_USE',
    INVALID_KEY = 'INVALID_KEY',
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
