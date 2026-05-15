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
      (Error as any).captureStackTrace(this, SiliconError);
    }
  }
}
