import { SiliconError, SiliconErrorCode } from '../../errors';
import NativeSilicon from '../../module';
import { hasOwn, isPlainObject } from '../../utils/validation';
import { androidAlgorithms, isAndroidAlgorithm, isAndroidHardwarePolicy, isIosAlgorithm, isIosHardwarePolicy, isKeyDigest, isKeyPurpose, isPubkeyFormat, isUserAuthPolicy, keyDigests, keyPurposeFamilies, keyPurposes, pubkeyFormats, userAuthPolicies } from './constants';
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

    opts = validateGenerateKeyOpts(opts);

    const result = await NativeSilicon.generateKey(alias, opts);
    if (!result.success) {
        switch (result.errorCode) {
            case "INVALID_ALGORITHM_PARAMETER":
                throw new SiliconError(SiliconErrorCode.INVALID_ALGORITHM_PARAMETER, result.errorMessage, { nativeStack: result.nativeStack });

            case 'ALIAS_IN_USE': 
                throw new SiliconError(SiliconErrorCode.ALIAS_IN_USE, result.errorMessage, { nativeStack: result.nativeStack });

            case "STRONGBOX_NOT_SUPPORTED":
                throw new SiliconError(SiliconErrorCode.STRONGBOX_NOT_SUPPORTED, result.errorMessage, { nativeStack: result.nativeStack });
            
            case "PURPOSE_WRAP_NOT_SUPPORTED":
                throw new SiliconError(SiliconErrorCode.PURPOSE_WRAP_NOT_SUPPORTED, result.errorMessage, { nativeStack: result.nativeStack });
            
            case "PURPOSE_AGREE_NOT_SUPPORTED":
                throw new SiliconError(SiliconErrorCode.PURPOSE_AGREE_NOT_SUPPORTED, result.errorMessage, { nativeStack: result.nativeStack });

            case "KEY_GENERATION_FAILED":
                throw new SiliconError(SiliconErrorCode.KEY_GENERATION_FAILED, result.errorMessage, { nativeStack: result.nativeStack });
        }

        throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`, { nativeStack: result.nativeStack });
    }

    return result.data;
}

function validateGenerateKeyOpts(opts: unknown): GenerateKeyOpts {
    if (opts !== undefined) {
        if (!isPlainObject(opts)) throw new TypeError("Silicon Error: 'opts' must be an object");

        if (hasOwn(opts, 'purposes') && opts.purposes !== undefined) {
            if (!Array.isArray(opts.purposes)) {
                throw new TypeError("Silicon Error: 'purposes' must be an array");
            }

            let family = null;
            for (const purpose of opts.purposes) {
                if (!isKeyPurpose(purpose)) {
                    throw new TypeError(`Silicon Error: purpose '${purpose}' is invalid, expected ${Object.values(keyPurposes).join("|")}`);
                }

                // Check if the purposes conflict
                const currentFamily = keyPurposeFamilies[purpose];
                if (family === null) family = currentFamily;
                if (currentFamily !== family) throw new TypeError(`Silicon Error: mutually exclusive purposes in ${opts.purposes.join(",")}`);
            }
        }

        if (hasOwn(opts, 'userAuth') && opts.userAuth !== undefined) {
            if (!isPlainObject(opts.userAuth)) throw new TypeError("Silicon Error: 'opts.userAuth' must be an object");

            if (hasOwn(opts.userAuth, 'require') && 
                opts.userAuth.require !== undefined &&
                typeof opts.userAuth.require !== 'boolean'
            ) {
                throw new TypeError("Silicon Error: 'opts.userAuth.require' must be of type 'boolean'");
            }

            if (hasOwn(opts.userAuth, 'timeout') &&
                opts.userAuth.timeout !== undefined && 
                typeof opts.userAuth.timeout !== 'number'
            ) {
                throw new TypeError("Silicon Error: 'opts.userAuth.timeout' must be of type 'number'");
            }

            if (hasOwn(opts.userAuth, 'invalidateOnEnrollment') && 
                opts.userAuth.invalidateOnEnrollment !== undefined &&
                typeof opts.userAuth.invalidateOnEnrollment !== 'boolean'
            ) {
                throw new TypeError("Silicon Error: 'opts.userAuth.invalidateOnEnrollment' must be of type 'boolean'");
            }

            if (hasOwn(opts.userAuth, 'policy') &&
                opts.userAuth !== undefined &&
                (typeof opts.userAuth.policy !== 'string' || !isUserAuthPolicy(opts.userAuth.policy)) 
            ) {
                throw new TypeError(`Silicon Error: 'opts.userAuth.policy' (${opts.userAuth.policy}) is invalid, expected ${Object.values(userAuthPolicies).join("|")}`);
            }
        }

        if (hasOwn(opts, 'attestChallenge') && 
            opts.attestChallenge !== undefined &&
            typeof opts.attestChallenge !== 'string'
        ) {
            throw new TypeError("Silicon Error: 'opts.attestChallenge' must be of type 'string'");
        }

        if (hasOwn(opts, 'pubkeyFormat') && 
            opts.pubkeyFormat !== undefined &&
            (typeof opts.pubkeyFormat !== 'string' || !isPubkeyFormat(opts.pubkeyFormat))
        ) {
            throw new TypeError(`Silicon Error: 'opts.pubkeyFormat' (${opts.pubkeyFormat}) is invalid, expected ${Object.values(pubkeyFormats).join("|")}`);
        }

        // Validate Android options
        if (hasOwn(opts, 'android') && opts.android !== undefined) {
            if (!isPlainObject(opts.android)) throw new TypeError("");

            if (hasOwn(opts.android, 'algorithm') && 
                opts.android.algorithm !== undefined &&
                (typeof opts.ios !== 'string' || !isAndroidAlgorithm(opts.android.algorithm))
            ) {
                throw new TypeError(`Silicon Error: 'opts.android.algorithm' (${opts.android.algorithm}) is invalid, expected ${Object.values(androidAlgorithms).join("|")}`);
            }

            if (hasOwn(opts.android, 'digests') && opts.android.digests !== undefined) {
                if (!Array.isArray(opts.android.digests)) throw new TypeError("Silicon Error: 'opts.android.digests' must be an array");

                for (const digest of opts.android.digests) {
                    if (!isKeyDigest(digest)) throw new TypeError(`Silicon Error: value (${digest}) in 'opts.android.digests' is invalid, expected ${Object.values(keyDigests).join("|")}`);
                }
            }

            if (hasOwn(opts.android, 'hardwarePolicy') &&
                opts.android.hardwarePolicy !== undefined &&
                (typeof opts.android.hardwarePolicy !== 'string' || !isAndroidHardwarePolicy(opts.android.hardwarePolicy))
            ) {
                throw new TypeError(`Silicon Error: 'opts.android.hardwarePolicy' (${opts.android.hardwarePolicy}) is invalid, expected ${Object.values(keyDigests).join("|")}`)
            }
        }

        // Validate iOS options
        if (hasOwn(opts, 'ios')) {
            if (!isPlainObject(opts.ios)) throw new TypeError("Silicon Error: 'opts.ios' must be an object");

            if (hasOwn(opts.ios, 'algorithm') &&
                opts.ios !== undefined &&
                (typeof opts.ios !== 'string' || !isIosAlgorithm(opts.ios))
            ) {
                throw new TypeError(`Silicon Error: 'opts.ios.algorithm' (${opts.ios.algorithm}) is invalid, expected ${Object.values(androidAlgorithms).join("|")}`);
            }

            if (hasOwn(opts.ios, 'digests') && opts.ios.digests !== undefined) {
                if (!Array.isArray(opts.ios.digests)) throw new TypeError("Silicon Error: 'opts.ios.digests' must be an array");

                for (const digest of opts.ios.digests) {
                    if (!isKeyDigest(digest)) throw new TypeError(`Silicon Error: value (${digest}) in 'opts.ios.digests' is invalid, expected ${Object.values(keyDigests).join("|")}`);
                }
            }

            if (hasOwn(opts.ios, 'hardwarePolicy') &&
                opts.ios.hardwarePolicy !== undefined &&
                (typeof opts.ios.hardwarePolicy !== 'string' || !isIosHardwarePolicy(opts.ios.hardwarePolicy))
            ) {
                throw new TypeError(`Silicon Error: 'opts.ios.hardwarePolicy' (${opts.ios.hardwarePolicy}) is invalid, expected ${Object.values(keyDigests).join("|")}`)
            }
        }

    } else {
        // Default opts to an empty object
        opts = {};
    }

    return opts as GenerateKeyOpts;
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
        if (result.errorCode == 'KEY_EXISTS_FAILED') {
            throw new SiliconError(SiliconErrorCode.KEY_EXISTS_FAILED, result.errorMessage, { nativeStack: result.nativeStack });
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
 * Gets the X.509 SPKI pubkey from an asymmetric keypair.
 * @param alias 
 * @param format 
 * @returns 
 */
export async function getPubKey(alias: string, format: keyof typeof pubkeyFormats): Promise<string> {
    if (!alias || typeof alias !== 'string') {
        throw new TypeError("Silicon Error: 'alias' must be of type string and not empty");
    }

    if (typeof format !== 'string' || 
        !isPubkeyFormat(format)
    ) {
        throw new TypeError(`Silicon Error: 'format' must be of type ${Object.values(pubkeyFormats).join("|")}`);
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
 * @param pubKeyFormat The format to use for the returned signingPubKey on iOS
 * @returns The certificate chain - An array of PEM strings
 */
export async function attestKey(alias: string, pubKeyFormat: keyof typeof pubkeyFormats): Promise<AttestResult> {
    if (!alias || typeof alias !== 'string') {
        throw new TypeError("Silicon Error: 'alias' must be of type string and not empty");
    }

    if (typeof pubKeyFormat !== 'string' || 
        !isPubkeyFormat(pubKeyFormat)
    ) {
        throw new TypeError(`Silicon Error: 'format' must be of type ${Object.values(pubkeyFormats).join("|")}`);
    }

    const result = await NativeSilicon.attestKey(alias, pubKeyFormat)
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

