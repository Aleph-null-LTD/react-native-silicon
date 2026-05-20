import { SiliconError, SiliconErrorCode } from '../../errors';
import NativeSilicon from '../../module';
import { hasOwn, isPlainObject } from '../../utils/validation';
import { androidAlgorithms, isAndroidAlgorithm, isAndroidHardwarePolicy, isKeyDigest, isKeyPurpose, isPubkeyFormat, isUserAuthPolicy, keyDigests, keyPurposes, pubkeyFormats, userAuthPolicies } from './constants';
import { AttestResult, GenerateKeyOpts, KeyInfo } from "./types";

/**
 * Generate a key
 * 
 * @param alias 
 * @param opts 
 * @returns 
 */
export async function generateKey(alias: string, opts?: GenerateKeyOpts): Promise<string> {
    if (!alias || typeof alias !== 'string') {
        throw new TypeError("Silicon Error: 'alias' must be of type string and not empty");
    }

    if (opts !== undefined) {
        if (!isPlainObject(opts)) throw new TypeError("Silicon Error: 'opts' must be an object");

        if (hasOwn(opts, 'purposes')) {
            if (!Array.isArray(opts.purposes)) {
                throw new TypeError("Silicon Error: 'purposes' must be an array");
            }

            for (const purpose of opts.purposes) {
                if (!isKeyPurpose(purpose)) {
                    throw new TypeError(`Silicon Error: purpose '${purpose}' is invalid, expected ${Object.values(keyPurposes).join("|")}`);
                }
            }
        }

        if (hasOwn(opts, 'userAuth')) {
            if (!isPlainObject(opts.userAuth)) throw new TypeError("Silicon Error: 'opts.userAuth' must be an object");

            if (hasOwn(opts.userAuth, 'require') && typeof opts.userAuth.require !== 'boolean') {
                throw new TypeError("Silicon Error: 'opts.userAuth.require' must be of type 'boolean'");
            }

            if (hasOwn(opts.userAuth, 'timeout') && typeof opts.userAuth.timeout !== 'number') {
                throw new TypeError("Silicon Error: 'opts.userAuth.timeout' must be of type 'number'");
            }

            if (hasOwn(opts.userAuth, 'invalidateOnEnrollment') && typeof opts.userAuth.invalidateOnEnrollment !== 'boolean') {
                throw new TypeError("Silicon Error: 'opts.userAuth.invalidateOnEnrollment' must be of type 'boolean'");
            }

            if (hasOwn(opts.userAuth, 'policy') && 
                (typeof opts.userAuth.policy !== 'string' || !isUserAuthPolicy(opts.userAuth.policy)) 
            ) {
                throw new TypeError(`Silicon Error: 'opts.userAuth.policy' (${opts.userAuth.policy}) is invalid, expected ${Object.values(userAuthPolicies).join("|")}`);
            }
        }

        if (hasOwn(opts, 'attestChallenge') && typeof opts.attestChallenge !== 'string') {
            throw new TypeError("Silicon Error: 'opts.attestChallenge' must be of type 'string'");
        }

        if (hasOwn(opts, 'pubkeyFormat') && 
            (typeof opts.pubkeyFormat !== 'string' || !isPubkeyFormat(opts.pubkeyFormat))
        ) {
            throw new TypeError(`Silicon Error: 'opts.pubkeyFormat' (${opts.pubkeyFormat}) is invalid, expected ${Object.values(pubkeyFormats).join("|")}`);
        }

        if (hasOwn(opts, 'android')) {
            if (!isPlainObject(opts.android)) throw new TypeError("");

            if (hasOwn(opts.android, 'algorithm') && !isAndroidAlgorithm(opts.android.algorithm)) {
                throw new TypeError(`Silicon Error: 'opts.android.algorithm' (${opts.android.algorithm}) is invalid, expected ${Object.values(androidAlgorithms).join("|")}`);
            }

            if (hasOwn(opts.android, 'digests')) {
                if (!Array.isArray(opts.android.digests)) throw new TypeError("Silicon Error: 'opts.android.digests' must be an array");

                for (const digest of opts.android.digests) {
                    if (!isKeyDigest(digest)) throw new TypeError(`Silicon Error: value (${digest}) in 'opts.android.digests' is invalid, expected ${Object.values(keyDigests).join("|")}`);
                }
            }

            if (hasOwn(opts.android, 'hardwarePolicy') &&
                (typeof opts.android.hardwarePolicy !== 'string' || !isAndroidHardwarePolicy(opts.android.hardwarePolicy))
            ) {
                throw new TypeError(`Silicon Error: 'opts.android.hardwarePolicy' (${opts.android.hardwarePolicy}) is invalid, expected ${Object.values(keyDigests).join("|")}`)
            }
        }

        // TODO: IOS options validation

    } else {
        // Default opts to an empty object
        opts = {};
    }

    const result = await NativeSilicon.genKey(alias, opts);
    if (!result.success) {
        switch (result.errorCode) {
            case "INVALID_ALGORITHM_PARAMETER":
                throw new SiliconError(SiliconErrorCode.INVALID_ALGORITHM_PARAMETER, result.errorMessage, { nativeStack: result.nativeStack });

            case "STRONGBOX_NOT_SUPPORTED":
                throw new SiliconError(SiliconErrorCode.STRONGBOX_NOT_SUPPORTED, result.errorMessage, { nativeStack: result.nativeStack });
            
            case "PURPOSE_WRAP_NOT_SUPPORTED":
                throw new SiliconError(SiliconErrorCode.PURPOSE_WRAP_NOT_SUPPORTED, result.errorMessage, { nativeStack: result.nativeStack });
            
            case "PURPOSE_AGREE_NOT_SUPPORTED":
                throw new SiliconError(SiliconErrorCode.PURPOSE_AGREE_NOT_SUPPORTED, result.errorMessage, { nativeStack: result.nativeStack });
        }

        throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack });
    }

    return result.data;
}

/**
 * Delete a key with the specified alias.
 * 
 * @param alias 
 * @returns true if the key was deleted
 */
export async function deleteKey(alias: string): Promise<boolean> {
    if (!alias || typeof alias !== 'string') {
        throw new TypeError("Silicon Error: 'alias' must be of type string and not empty");
    }
    
    const result = await NativeSilicon.deleteKey(alias);
    if (!result.success) {
        if (result.errorCode == 'DELETE_FAILED') {
            throw new SiliconError(SiliconErrorCode.DELETE_FAILED, result.errorMessage, { nativeStack: result.nativeStack });
        }

        throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack });
    }

    return result.data;
}

/**
 * USE WITH CAUTION.
 * 
 * When 'prefix' is undefined, this function deletes all keys generated by the entire app, 
 * not just the keys generated by react-native-silicon.
 * If you are using other libs (e.g., expo-secure-store) this will delete all keys generated by them too.
 * 
 * We recommended that you prefix all your key aliases so that you can bulk delete using the 'prefix' param as a filter.
 * 
 * @param prefix When set, only keys with the specified prefix will be deleted
 * @returns The number of keys that were deleted
 */
export async function deleteAllKeys(prefix?: string): Promise<number> {
    if (prefix !== undefined && typeof prefix !== 'string') {
        throw new TypeError("Silicon Error: 'prefix' must be of type string");
    }

    const result = await NativeSilicon.deleteAllKeys(prefix);
    if (!result.success) {
        if (result.errorCode == 'BULK_DELETE_FAILED') {
            throw new SiliconError(SiliconErrorCode.BULK_DELETE_FAILED, result.errorMessage, { nativeStack: result.nativeStack });
        }

        throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack });
    }

    return result.data;
}

/**
 * Checks for the existence of a key with the specified alias.
 * 
 * @param alias 
 * @returns true if the key exists
 */
export async function keyExists(alias: string): Promise<boolean> {
    if (!alias || typeof alias !== 'string') {
        throw new TypeError("Silicon Error: 'alias' must be of type string and not empty");
    }

    const result = await NativeSilicon.keyExists(alias);
    if (!result.success) {
        if (result.errorCode == 'KEY_CHECK_FAILED') {
            throw new SiliconError(SiliconErrorCode.KEY_CHECK_FAILED, result.errorMessage, { nativeStack: result.nativeStack });
        }

        throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack });
    }

    return result.data;
}

/**
 * Lists all keys.
 * 
 * prefix can be defined to list only keys with a matching prefix.
 * 
 * @param prefix 
 * @returns An array of the key aliases
 */
export async function listKeys(prefix?: string): Promise<string[]> {
    if (prefix !== undefined && typeof prefix !== 'string') {
        throw new TypeError("Silicon Error: 'prefix' must be of type string");
    }

    const result = await NativeSilicon.listKeys(prefix)
    if (!result.success) {
        if (result.errorCode == 'KEY_LIST_FAILED') {
            throw new SiliconError(SiliconErrorCode.KEY_LIST_FAILED, result.errorMessage, { nativeStack: result.nativeStack });
        }

        throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack });
    }

    return result.data;
}

/**
 * Validates the specified key
 * @param alias 
 * @returns 
 * * 'VALID' - If the key is valid and ready for use
 * * 'MISSING' - If the key does not exist
 * * 'INVALIDATED' - If the key was invalidated because new biometrics were enrolled
 * * 'UNRECOVERABLE' - If the key is in an unrecoverable state
 */
export async function validateKey(alias: string): Promise<'VALID' | 'MISSING' | 'INVALIDATED' | 'UNRECOVERABLE'> {
    if (!alias || typeof alias !== 'string') {
        throw new TypeError("Silicon Error: 'alias' must be of type string and not empty");
    }

    const result = await NativeSilicon.validateKey(alias)
    if (!result.success) {
        if (result.errorCode == 'KEY_VALIDATION_FAILED') {
            throw new SiliconError(SiliconErrorCode.KEY_VALIDATION_FAILED, result.errorMessage, { nativeStack: result.nativeStack });
        }

        throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack });
    }

    return result.data;
}

/**
 * Gets the pubkey from an asymmetric keypair.
 * @param alias 
 * @param format 
 * @returns 
 */
export async function getPubKey(alias: string, format: 'PEM' | 'B64'): Promise<string> {
    if (!alias || typeof alias !== 'string') {
        throw new TypeError("Silicon Error: 'alias' must be of type string and not empty");
    }

    if (typeof format !== 'string' || 
        (format !== 'PEM' && format !== 'B64')
    ) {
        throw new TypeError("Silicon Error: 'format' must be of type 'PEM' | 'B64'");
    }

    const result = await NativeSilicon.getPubKey(alias, format);
    if (!result.success) {
        switch (result.errorCode) {
            case 'KEY_NOT_FOUND':
                throw new SiliconError(SiliconErrorCode.KEY_NOT_FOUND, result.errorMessage, { nativeStack: result.nativeStack })

            case 'NO_CERT':
                throw new SiliconError(SiliconErrorCode.NO_CERT, result.errorMessage, { nativeStack: result.nativeStack })

            case 'UNSUPPORTED_KEY_FAMILY':
                throw new SiliconError(SiliconErrorCode.UNSUPPORTED_KEY_FAMILY, result.errorMessage, { nativeStack: result.nativeStack })

            case 'GET_PUB_KEY_FAILED':
                throw new SiliconError(SiliconErrorCode.GET_PUB_KEY_FAILED, result.errorMessage, { nativeStack: result.nativeStack })
        }

        throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack });
    }

    return result.data;
}

/**
 * Gets the certificate chain for attestation.
 * 
 * IMPORTANT: This will only work if an attestation challenge was provided when the
 * key was generated (see the generateKey options)
 * 
 * @param alias
 * @returns The certificate chain - An array of PEM strings
 */
export async function attestKey(alias: string): Promise<AttestResult> {
    if (!alias || typeof alias !== 'string') {
        throw new TypeError("Silicon Error: 'alias' must be of type string and not empty");
    }

    const result = await NativeSilicon.attestKey(alias)
    if (!result.success) {
        switch (result.errorCode) {
            case 'KEY_NOT_FOUND':
                throw new SiliconError(SiliconErrorCode.KEY_NOT_FOUND, result.errorMessage, { nativeStack: result.nativeStack });

            case 'NO_CERT_CHAIN':
                throw new SiliconError(SiliconErrorCode.NO_CERT_CHAIN, result.errorMessage, { nativeStack: result.nativeStack })

            case 'ATTEST_FAILED':
                throw new SiliconError(SiliconErrorCode.ATTEST_FAILED, result.errorMessage, { nativeStack: result.nativeStack })

            case 'NO_ATTEST_CHALLENGE':
                throw new SiliconError(SiliconErrorCode.NO_ATTEST_CHALLENGE, result.errorMessage, { nativeStack: result.nativeStack })

            default:
                throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack });
        }
    }

    return result.data;
}

/**
 * Gets info about the specified key.
 * 
 * @param alias 
 * @returns KeyInfo object
 */
export async function getKeyInfo(alias: string): Promise<KeyInfo> {
    if (!alias || typeof alias !== 'string') {
        throw new TypeError("Silicon Error: 'alias' must be of type string and not empty");
    }

    const result = await NativeSilicon.getKeyInfo(alias)
    if (!result.success) {
        switch (result.errorCode) {
            case 'KEY_NOT_FOUND':
                throw new SiliconError(SiliconErrorCode.KEY_NOT_FOUND, result.errorMessage, { nativeStack: result.nativeStack });

            case 'GET_KEY_INFO_FAILED':
                throw new SiliconError(SiliconErrorCode.GET_KEY_INFO_FAILED, result.errorMessage, { nativeStack: result.nativeStack });

            case 'UNSUPPORTED_KEY_FAMILY':
                throw new SiliconError(SiliconErrorCode.UNSUPPORTED_KEY_FAMILY, result.errorMessage, { nativeStack: result.nativeStack });

            case 'KEY_LOAD_FAILED':
                throw new SiliconError(SiliconErrorCode.KEY_LOAD_FAILED, result.errorMessage, { nativeStack: result.nativeStack });
        }

        throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack });
    }

    // Remove the curve from the KeyInfo if it is null (i.e., not an EC key)
    if (result.data.curve == null) delete result.data.curve;

    return result.data;
}

/*
export function isHardwareBacked(alias: string) {
    if (!alias || typeof alias !== 'string') {
        throw new TypeError("Silicon Error: 'alias' must be of type string and not empty");
    }
}
*/

