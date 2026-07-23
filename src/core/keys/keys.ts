import { SiliconError, SiliconErrorCode } from '../../errors';
import NativeSilicon from '../../module';
import { handleBridgeResult } from '../../utils/handle-bridge-result';
import { ensureUint8Array } from '../../utils/bytes';
import { hasOwn, isPlainObject, isSafeNumber } from '../../utils/validation';
import { 
    androidAlgorithms, 
    isAndroidAlgorithm, 
    isAndroidHardwarePolicy, 
    isIosAlgorithm, 
    isIosHardwarePolicy, 
    isKeyDigest, 
    isKeyPurpose, 
    isPubkeyFormat, 
    isSignaturePaddingAlgorithm, 
    isUserAuthPolicy, 
    keyDigests, 
    keyPurposeFamilies, 
    keyPurposes, 
    pubkeyFormats, 
    signaturePaddingAlgorithms, 
    userAuthPolicies 
} from './constants';
import { AttestResult, GenerateKeyOpts, KeyInfo, PubkeyFormat, PubKeyFormatTypeMap } from "./types";

/**
 * Generate a key
 * 
 * @param alias 
 * @param opts 
 * @returns 
 */
export async function generateKey(alias: string, opts?: GenerateKeyOpts): Promise<void> {
    if (!alias || typeof alias !== 'string' || alias.trim().length < 1) {
        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] alias must be of type string and not empty");
    }

    opts = validateGenerateKeyOpts(opts);

    // Uint8Array fails to map correctly when passed over the bridge if it is nested inside an object
    // so we extract the attest challenge (if provided) and pass it as a top level parameter so it can be correctly mapped on the native side
    const attestChallenge = opts.attestChallenge;

    const result = await NativeSilicon.generateKey(alias, opts ?? {}, attestChallenge);
    handleBridgeResult(result);
}

function validateGenerateKeyOpts(opts: GenerateKeyOpts | undefined): GenerateKeyOpts {
    if (opts !== undefined) {
        if (!isPlainObject(opts)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts must be a plain object. If you are using a class or builder pattern, spread the object first: { ...myConfig }");

        if (hasOwn(opts, 'purposes') && opts.purposes !== undefined) {
            if (!Array.isArray(opts.purposes)) {
                throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] purposes must be an array");
            }

            if (opts.purposes.length == 0) {
                throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] purposes must not be empty (leave it undefined for default value)");
            }

            // Ensure that purpose families cannot be mixed
            let family = null;
            for (const purpose of opts.purposes) {
                if (!isKeyPurpose(purpose)) {
                    throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] purpose is invalid, expected ${Object.values(keyPurposes).join("|")}`);
                }

                // Check if the purposes conflict
                const currentFamily = keyPurposeFamilies[purpose];
                if (family === null) family = currentFamily;
                if (currentFamily !== family) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] mutually exclusive purposes in ${opts.purposes.join(",")}`);
            }

            opts.purposes.forEach(
                (val) => {
                    if (val == keyPurposes.AGREE ||
                        val == keyPurposes.ENCRYPT ||
                        val == keyPurposes.DECRYPT ||
                        val == keyPurposes.WRAP
                    ) {
                        throw new Error(`[RN-Silicon] Purpose (${opts!.purposes}) is not yet implemented`);
                    }
                }
            )

            // Ensure purposes inherit 
            if (opts.purposes[0] == keyPurposes.SIGN || opts.purposes[0] == keyPurposes.VERIFY) {
                opts.purposes = [keyPurposes.SIGN, keyPurposes.VERIFY];
            }
            if (opts.purposes[0] == keyPurposes.ENCRYPT || opts.purposes[0] == keyPurposes.DECRYPT) {
                opts.purposes = [keyPurposes.ENCRYPT, keyPurposes.DECRYPT];
            }
        }

        if (hasOwn(opts, 'userAuth') && opts.userAuth !== undefined) {
            if (!isPlainObject(opts.userAuth)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.userAuth must be a plain object. If you are using a class or builder pattern, spread the object first: { ...myConfig }");

            if (hasOwn(opts.userAuth, 'require') && 
                opts.userAuth.require !== undefined &&
                typeof opts.userAuth.require !== 'boolean'
            ) {
                throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.userAuth.require must be of type boolean");
            }

            if (hasOwn(opts.userAuth, 'timeout')) {
                if (opts.userAuth.timeout !== undefined) {
                    if (!isSafeNumber(opts.userAuth.timeout)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.userAuth.timeout must be of type number");
                    
                    if (opts.userAuth.timeout < 0 || opts.userAuth.timeout > 6000) {
                        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.userAuth.timeout must be >=0 AND <=6000");
                    }
                }
            }

            if (hasOwn(opts.userAuth, 'invalidateOnEnrollment') && 
                opts.userAuth.invalidateOnEnrollment !== undefined &&
                typeof opts.userAuth.invalidateOnEnrollment !== 'boolean'
            ) {
                throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.userAuth.invalidateOnEnrollment must be of type boolean");
            }

            if (hasOwn(opts.userAuth, 'policy') &&
                opts.userAuth !== undefined &&
                (typeof opts.userAuth.policy !== 'string' || !isUserAuthPolicy(opts.userAuth.policy)) 
            ) {
                throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] opts.userAuth.policy is invalid, expected ${Object.values(userAuthPolicies).join(" | ")}`);
            }
        }

        if (hasOwn(opts, 'attestChallenge') && 
            opts.attestChallenge !== undefined &&
            !(opts.attestChallenge instanceof Uint8Array)
        ) {
            throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.attestChallenge must be of type Uint8Array");
        }

        // Validate Android options
        if (hasOwn(opts, 'android') && opts.android !== undefined) {
            if (!isPlainObject(opts.android)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.android must be a plain object. If you are using a class or builder pattern, spread the object first: { ...myConfig }");

            if (hasOwn(opts.android, 'algorithm') && 
                opts.android.algorithm !== undefined &&
                (typeof opts.android.algorithm !== 'string' || !isAndroidAlgorithm(opts.android.algorithm))
            ) {
                throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] opts.android.algorithm is invalid, expected ${Object.values(androidAlgorithms).join(" | ")}`);
            }

            if (hasOwn(opts.android, 'digests') && opts.android.digests !== undefined) {
                if (!Array.isArray(opts.android.digests)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.android.digests must be an array");

                if (opts.android.digests.length < 1) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.android.digests must have at least one element");

                for (const digest of opts.android.digests) {
                    if (!isKeyDigest(digest)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] value (${digest}) in opts.android.digests is invalid, expected ${Object.values(keyDigests).join(" | ")}`);
                }
            }

            if (hasOwn(opts.android, 'signaturePaddingAlgorithm') && 
                opts.android.signaturePaddingAlgorithm !== undefined &&
                (typeof opts.android.signaturePaddingAlgorithm !== 'string' || !isSignaturePaddingAlgorithm(opts.android.signaturePaddingAlgorithm))
            ) {
                throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] value ${opts.android.signaturePaddingAlgorithm} in opts.android.signaturePaddingAlgorithm is invalid, expected ${Object.values(signaturePaddingAlgorithms).join(" | ")}`);
            }

            if (hasOwn(opts.android, 'hardwarePolicy') &&
                opts.android.hardwarePolicy !== undefined &&
                (typeof opts.android.hardwarePolicy !== 'string' || !isAndroidHardwarePolicy(opts.android.hardwarePolicy))
            ) {
                throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] opts.android.hardwarePolicy is invalid, expected ${Object.values(keyDigests).join(" | ")}`)
            }
        }

        // Validate iOS options
        if (hasOwn(opts, 'ios')) {
            if (!isPlainObject(opts.ios)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.ios must be a plain object. If you are using a class or builder pattern, spread the object first: { ...myConfig }");

            if (hasOwn(opts.ios, 'algorithm') &&
                opts.ios.algorithm !== undefined &&
                (typeof opts.ios.algorithm !== 'string' || !isIosAlgorithm(opts.ios.algorithm))
            ) {
                throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] opts.ios.algorithm is invalid, expected ${Object.values(androidAlgorithms).join(" | ")}`);
            }

            if (hasOwn(opts.ios, 'digests') && opts.ios.digests !== undefined) {
                if (!Array.isArray(opts.ios.digests)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.ios.digests must be an array");

                if (opts.ios.digests.length < 1) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] opts.ios.digests must have at least one element");

                for (const digest of opts.ios.digests) {
                    if (!isKeyDigest(digest)) throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] value in opts.ios.digests is invalid, expected ${Object.values(keyDigests).join(" | ")}`);
                }
            }

            if (hasOwn(opts.ios, 'signaturePaddingAlgorithm') && 
                opts.ios.signaturePaddingAlgorithm !== undefined &&
                !isSignaturePaddingAlgorithm(opts.ios.signaturePaddingAlgorithm)
            ) {
                throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] value in opts.ios.signaturePaddingAlgorithm is invalid, expected ${Object.values(signaturePaddingAlgorithms).join(" | ")}`);
            }

            if (hasOwn(opts.ios, 'hardwarePolicy') &&
                opts.ios.hardwarePolicy !== undefined &&
                (typeof opts.ios.hardwarePolicy !== 'string' || !isIosHardwarePolicy(opts.ios.hardwarePolicy))
            ) {
                throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] opts.ios.hardwarePolicy is invalid, expected ${Object.values(keyDigests).join(" | ")}`)
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
 * @returns true if the key was deleted, false if key not found
 */
export async function deleteKey(alias: string): Promise<boolean> {
    if (!alias || typeof alias !== 'string' || alias.trim().length < 1) {
        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] alias must be of type string and not empty");
    }
    
    const result = await NativeSilicon.deleteKey(alias);
    return handleBridgeResult(result);
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
    if (prefix !== undefined && (typeof prefix !== 'string' || prefix.trim().length < 1)) {
        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] prefix must be of type string");
    }

    const result = await NativeSilicon.deleteAllKeys(prefix);
    return handleBridgeResult(result);
}

/**
 * Checks for the existence of a key with the specified alias.
 * 
 * @param alias 
 * @returns true if the key exists
 */
export async function keyExists(alias: string): Promise<boolean> {
    if (!alias || typeof alias !== 'string' || alias.trim().length < 1) {
        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] alias must be of type string and not empty");
    }

    const result = await NativeSilicon.keyExists(alias);
    return handleBridgeResult(result);
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
        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] prefix must be of type string");
    }

    const result = await NativeSilicon.listKeys(prefix)
    return handleBridgeResult(result);
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
    if (!alias || typeof alias !== 'string' || alias.trim().length < 1) {
        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] alias must be of type string and not empty");
    }

    const result = await NativeSilicon.validateKey(alias)
    return handleBridgeResult(result);
}

/**
 * Gets the X.509 SPKI pubkey from an asymmetric keypair.
 * @param alias 
 * @param format 
 * @returns 
 */
export async function getPubKey<F extends PubkeyFormat>(alias: string, format: F): Promise<PubKeyFormatTypeMap[F]> {
    if (!alias || typeof alias !== 'string' || alias.trim().length < 1) {
        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] alias must be of type string and not empty");
    }

    if (typeof format !== 'string' || 
        !isPubkeyFormat(format)
    ) {
        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] format must be of type ${Object.values(pubkeyFormats).join("|")}`);
    }

    const result = await NativeSilicon.getPubKey(alias, format);
    const pubKey = handleBridgeResult(result);

    let ret: PubKeyFormatTypeMap[F];
    if (format == "SPKI") {
        ret = ensureUint8Array(pubKey) as PubKeyFormatTypeMap[F];

    } else {
        if (typeof pubKey != 'string') {
            throw new SiliconError(SiliconErrorCode.INTERNAL_ERROR, `[RN-Silicon] returned data was not of type string when format was set to ${format}`);
        }

        ret = pubKey;
    }

    return ret;
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
export async function attestKey<F extends PubkeyFormat>(alias: string, pubKeyFormat: F): Promise<AttestResult<F>> {
    if (!alias || typeof alias !== 'string' || alias.trim().length < 1) {
        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] alias must be of type string and not empty");
    }

    if (typeof pubKeyFormat !== 'string' || 
        !isPubkeyFormat(pubKeyFormat)
    ) {
        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, `[RN-Silicon] format must be of type ${Object.values(pubkeyFormats).join("|")}`);
    }

    const result = await NativeSilicon.attestKey(alias, pubKeyFormat);
    const attestResult = handleBridgeResult(result);

    if (attestResult.platform === "IOS") {
        if (pubKeyFormat === "SPKI") {
            attestResult.signingPubKey = ensureUint8Array(attestResult.signingPubKey) as PubKeyFormatTypeMap[F];

        } else if (typeof attestResult.signingPubKey != 'string') {
            throw new SiliconError(
                SiliconErrorCode.INTERNAL_ERROR, 
                `[RN-Silicon] returned data was not of type string when pubKeyFormat was set to ${pubKeyFormat}`
            );
        }
    }

    return attestResult;
}

/**
 * Gets info about the specified key.
 * 
 * @param alias 
 * @returns KeyInfo object
 */
export async function getKeyInfo(alias: string): Promise<KeyInfo> {
    if (!alias || typeof alias !== 'string' || alias.trim().length < 1) {
        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] alias must be of type string and not empty");
    }

    const result = await NativeSilicon.getKeyInfo(alias)
    const keyInfo = handleBridgeResult(result);

    // Remove the curve from the KeyInfo if it is null (i.e., not an EC key)
    if (keyInfo.curve == null) delete keyInfo.curve;

    return keyInfo;
}

/*
export function isHardwareBacked(alias: string) {
    if (!alias || typeof alias !== 'string') {
        throw new SiliconError(SiliconErrorCode.INVALID_ARGUMENT, "[RN-Silicon] alias must be of type string and not empty");
    }
}
*/

