import { SiliconError, SiliconErrorCode } from '../../errors';
import NativeSilicon from '../../module';
import { handleBridgeResult } from '../../utils/handle-bridge-result';
import { hasOwn, isPlainObject } from '../../utils/validation';
import { isSignDigest, isSignEncoding, isSignFormat, isVerifyAlgorithm, signDigest, signEncodings, signFormats, verifyAlgorithms } from './constants';
import { SignOpts, VerifyOpts } from './types';

// ---- Sign & Verify ----

/**
 * Signs the given payload using the key specified by 'alias'
 * @param alias 
 * @param payload 
 * @param opts 
 * @returns 
 * @note Will automatically prompt for user authentication if enabled on the key
 */
export async function sign(alias: string, payload: string | Uint8Array, opts?: SignOpts): Promise<string> {
    if (typeof alias !== 'string' || alias.trim().length < 1) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] alias must be of type string and must not be empty");

    if (typeof payload !== 'string' && !(payload instanceof Uint8Array)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] payload must be of type string | Uint8Array");
    if (typeof payload === 'string' && payload.trim().length < 1) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] string payload must not be empty");

    let payloadStr: string | null = null;
    let payloadByteArr: Uint8Array | null = null;

    if (typeof payload == 'string') {
        payloadStr = payload;
    } else {
        payloadByteArr = payload;
    }

    if (opts !== undefined) {
        if (!isPlainObject(opts)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts must be of type object");
        
        if (hasOwn(opts, 'encoding') &&
            opts.encoding !== undefined &&
            !isSignEncoding(opts.encoding)
        ) {
            throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] opts.encoding must be of type ${Object.values(signEncodings).join("|")}`);
        }
        
        if (hasOwn(opts, 'digest') &&
            opts.digest !== undefined &&
            (typeof opts.digest !== 'string' || !isSignDigest(opts.digest))
        ) {
            throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] opts.digest must be of type ${Object.values(signDigest).join("|")}`);
        }

        if (hasOwn(opts, 'format') &&
            opts.format !== undefined &&
            !isSignFormat(opts.format)
        ) {
            throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] opts.format must be of type ${Object.values(signFormats).join("|")}`);
        }
    } else {
        opts = {};
    }

    const result = await NativeSilicon.sign(alias, payloadStr, payloadByteArr, opts);
    return handleBridgeResult(result);
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
    if ((typeof payload !== 'string' || payload.trim().length < 1) && !(payload instanceof Uint8Array)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] payload must be of type string | Uint8Array. And must not be an empty string");

    let payloadStr: string | null = null;
    let payloadByteArr: Uint8Array | null = null;

    if (typeof payload == 'string') {
        payloadStr = payload;
    } else {
        payloadByteArr = payload;
    }

    if (typeof signature !== 'string' || signature.trim().length < 1) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] signature must be of type string");
    
    if (!isPlainObject(opts)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts must be a valid options object");

    // TODO: Ensure that either pubkey or alias is present, but not both
    let pubkey;
    if (hasOwn(opts, 'pubkey')) {
        if (typeof opts.pubkey !== 'string' || opts.pubkey.trim().length < 1) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.pubkey must be of type string");

        pubkey = opts.pubkey
            .replace(PEM_REGEX, '')
            .replace('\n', '')
            .replace('\r', '')
            .trim();
    }

    let alias: string | undefined = undefined;
    if (hasOwn(opts, 'alias')) {
        if (typeof opts.alias !== 'string' || opts.alias.trim().length < 1) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.alias must be of type string and not empty");

        alias = opts.alias;
    }

    // Ensure that only either alias or pubkey is present
    if (alias && pubkey) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.alias and opts.pubkey are mutually exclusive");
    if (!alias && !pubkey) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] either opts.alias or opts.pubkey must be supplied");

    if (pubkey && !hasOwn(opts, 'algorithm')) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts must contain the algorithm property");
    if (pubkey || (alias && hasOwn(opts, 'algorithm') && opts.algorithm !== undefined)) {
        if (typeof opts.algorithm !== 'string') throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.algorithm must be of type string");
        if (!isVerifyAlgorithm(opts.algorithm)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] opts.algorithm must be of type ${Object.values(verifyAlgorithms).join("|")}`);
    }

    // Normalize all signatures to standard Base64 with padding
    const signatureB64 = normalizeToBase64(signature);

    const result = await NativeSilicon.verify(
        payloadStr, 
        payloadByteArr,
        signatureB64,
        {
            alias: alias,
            pubkeyB64: pubkey,
            algorithm: opts.algorithm
        }
    );
    return handleBridgeResult(result);
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

// ---- Symmetric Encryption ----

/*
export function encrypt(alias: string, data) {

}

export function decrypt(alias: string, cipherText) {
    
}
*/
