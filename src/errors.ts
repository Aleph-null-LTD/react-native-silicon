export enum SiliconErrorCode {
  PLATFORM_NOT_SUPPORTED = 'PLATFORM_NOT_SUPPORTED',
  KEY_NOT_FOUND = 'KEY_NOT_FOUND',
  KEY_INVALIDATED = 'KEY_INVALIDATED',
  UNSUPPORTED_KEY_FAMILY = 'UNSUPPORTED_KEY_FAMILY',
  SIGNING_FAILED = 'SIGNING_FAILED',
  HARDWARE_NOT_AVAILABLE = 'HARDWARE_NOT_AVAILABLE',
  BIOMETRICS_NOT_ENROLLED = 'BIOMETRICS_NOT_ENROLLED',
  USER_CANCELLED = 'USER_CANCELLED',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  DELETE_FAILED = 'DELETE_FAILED',
  BULK_DELETE_FAILED = 'BULK_DELETE_FAILED',
  ATTESTATION_FAILED = 'ATTESTATION_FAILED',
  UNKNOWN_NATIVE_ERROR = 'UNKNOWN_NATIVE_ERROR',
};

export class SiliconError extends Error {
  readonly code: SiliconErrorCode;
  readonly nativeStack?: string;

  constructor(code: SiliconErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = 'SiliconError';
    this.code = code;
    this.cause = cause; 
    
    // Maintain stack trace (standard JS)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, SiliconError);
    }
  }
}
