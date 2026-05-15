import { SiliconError, SiliconErrorCode } from '../../errors';
import NativeSilicon from '../../module';
import { hasOwn, isPlainObject } from '../../utils/validation';
import { isSignAlgorithm, isSignEncoding, isSignFormat, isVerifyAlgorithm, signAlgorithms, signEncodings, signFormats, verifyAlgorithms } from './constants';
import { SignOpts, VerifyOpts } from './types';

// -- Raw Sign & Verify --

/**
 * Signs the given payload using the key specified by 'alias'
 * 
 * @param alias 
 * @param payload 
 * @param opts 
 * @returns 
 * @note Will automatically prompt for user authentication if enabled on the key
 */
export async function sign(alias: string, payload: string | Uint8Array, opts: SignOpts): Promise<string> {
    if (typeof alias !== 'string') throw new TypeError("Silicon Error: 'alias' must be of type 'string'");

    if (typeof payload !== 'string' && !(payload instanceof Uint8Array)) throw new TypeError("Silicon Error: 'payload' must be of type 'string' | 'Uint8Array'");

    if (!isPlainObject(opts)) throw new TypeError("Silicon Error: 'opts' must be of type 'object'");
    
    if (!hasOwn(opts, 'encoding')) throw new TypeError("Silicon Error: 'opts' must contain the 'encoding' property");
    if (!isSignEncoding(opts.encoding)) throw new TypeError(`Silicon Error: 'opts.encoding' must be of type ${Object.values(signEncodings).join("|")}`);
    
    if (!hasOwn(opts, 'algorithm')) throw new TypeError("Silicon Error: 'opts' must contain the 'algorithm' property");
    if (!isSignAlgorithm(opts.algorithm)) throw new TypeError(`Silicon Error: 'opts.algorithm' must be of type ${Object.values(signAlgorithms).join("|")}`);

    if (hasOwn(opts, 'format') && !isSignFormat(opts.format)) {
        throw new TypeError(`Silicon Error: 'opts.format' must be of type ${Object.values(signFormats).join("|")}`);
    }
    
    const result = await NativeSilicon.sign(alias, payload, opts);
    if (!result.success) {
        switch (result.errorCode) {
            case 'KEY_NOT_FOUND':
                throw new SiliconError(SiliconErrorCode.KEY_NOT_FOUND, result.errorMessage, { nativeStack: result.nativeStack });

            case 'KEY_INVALIDATED':
                throw new SiliconError(SiliconErrorCode.KEY_INVALIDATED, result.errorMessage, { nativeStack: result.nativeStack });

            case 'UNSUPPORTED_KEY_FAMILY':
                throw new SiliconError(SiliconErrorCode.UNSUPPORTED_KEY_FAMILY, result.errorMessage, { nativeStack: result.nativeStack });

            case 'SIGNING_FAILED':
            case 'PROMPT_SIGN_FAILED':
                throw new SiliconError(SiliconErrorCode.SIGNING_FAILED, result.errorMessage, { nativeStack: result.nativeStack });
            
            default:
                throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack });
        }
    }

    return result.data;
}

// Regex to match PEM headers/footers
const PEM_REGEX = /(?:-----BEGIN.*?-----|-----END.*?-----|\\s+)/g;

/**
 * Verifies a signature with either: 
 * * An internal asymmetric keypair - if alias is set in opts
 * * The supplied public key - if pubkey is set in opts
 * 
 * @param payload The payload to verify
 * @param signature The signature to verify against - can be either Base64 or Base64Url
 * @param opts 
 * @returns
 */
export async function verify(payload: string | Uint8Array, signature: string, opts: VerifyOpts): Promise<boolean> {
    if (typeof payload !== 'string' && !(payload instanceof Uint8Array)) throw new TypeError("Silicon Error: 'payload' must be of type 'string' | 'Uint8Array'");

    if (typeof signature !== 'string') throw new TypeError("Silicon Error: 'signature' must be of type 'string'");
    
    if (!isPlainObject(opts)) throw new TypeError("Silicon Error: 'opts' must be of type 'object'");

    if (!hasOwn(opts, 'algorithm')) throw new TypeError("Silicon Error: 'opts' must contain the 'algorithm' property");
    if (typeof opts.algorithm !== 'string') throw new TypeError("Silicon Error: 'opts.algorithm' must be of type 'string'");
    if (!isVerifyAlgorithm(opts.algorithm)) throw new TypeError(`Silicon Error: 'opts.algorithm' must be of type ${Object.values(verifyAlgorithms).join("|")}`);

    // TODO: Ensure that either pubkey or alias is present, but not both
    let pubkey;
    if (hasOwn(opts, 'pubkey')) {
        if (typeof opts.pubkey !== 'string') throw new TypeError("Silicon Error: 'opts.pubkey' must be of type 'string'");

        pubkey = opts.pubkey
            .replace(PEM_REGEX, '')
            .replace('\n', '')
            .replace('\r', '')
            .trim();
    }

    let alias: string | undefined = undefined;
    if (hasOwn(opts, 'alias')) {
        if (typeof opts.alias !== 'string') throw new TypeError("Silicon Error: 'opts.alias' must be of type 'string'");

        alias = opts.alias;
    }

    // Ensure that only either alias or pubkey is present
    if (alias && pubkey) throw TypeError("Silicon Error: 'opts.alias' and 'opts.pubkey' are mutually exclusive");
    if (!alias && !pubkey) throw TypeError("Silicon Error: either 'opts.alias' or 'opts.pubkey' must be supplied");

    // Normalize all signatures to standard Base64 with padding
    const signatureB64 = normalizeToBase64(signature);

    const result = await NativeSilicon.verify(
        payload, 
        signatureB64,
        {
            alias: alias,
            pubkeyB64: pubkey,
            algorithm: opts.algorithm
        }
    );
    if (!result.success) {
        switch (result.errorCode) {
            case 'KEY_NOT_FOUND':
                throw new SiliconError(SiliconErrorCode.KEY_NOT_FOUND, result.errorMessage, { nativeStack: result.nativeStack });

            case 'NO_CERT':
                throw new SiliconError(SiliconErrorCode.NO_CERT, result.errorMessage, { nativeStack: result.nativeStack });

            case 'VERIFICATION_FAILED':
                throw new SiliconError(SiliconErrorCode.VERIFICATION_FAILED, result.errorMessage, { nativeStack: result.nativeStack });

            default:
                throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack });
        }
    }

    return result.data;
}

const HYPHEN_REGEX = /-/g;
const UNDERSCORE_REGEX = /_/g;

/**
 * Converts Base64Url strings into standard Base64 strings 
 * and automatically injects missing '=' padding.
 */
function normalizeToBase64(input: string): string {
  // Convert URL-safe characters back to standard Base64 characters
  let base64 = input.replace(HYPHEN_REGEX, '+').replace(UNDERSCORE_REGEX, '/');

  // Restore standard 4-byte alignment padding if missing
  while (base64.length % 4) {
    base64 += '=';
  }

  return base64;
}

// -- Hardware-Backed Symmetric Encryption --

/*
export function encrypt(alias: string, data) {

}

export function decrypt(alias: string, cipherText) {
    
}
*/
