import { SiliconError, SiliconErrorCode } from '../../errors';
import NativeSilicon from '../../module';
import { GenerateKeyOpts } from "./types";

/**
 * Generate a key
 * 
 * @param alias 
 * @param opts 
 * @returns 
 */
export async function generateKey(alias: string, opts: GenerateKeyOpts): Promise<string> {
    const result = await NativeSilicon.genKey(alias, opts);
    if (!result.success) {
        throw new SiliconError()
    }

    return result.data;
}

/**
 * Delete a key
 * 
 * @param alias 
 * @returns true if the key was deleted
 */
export async function deleteKey(alias: string): Promise<boolean> {
    const result = await NativeSilicon.deleteKey(alias);
    if (!result.success) {
        if (result.errorCode == 'DELETE_FAILED') {
            throw new SiliconError(SiliconErrorCode.DELETE_FAILED, result.errorMessage)
        }

        throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`)
    }

    return result.data;
}

export function deleteAllKeys() {
    
}

export function keyExists(alias: string): boolean {

}

export function listKeys() {

}

export function validateKey(alias: string) {

}

export function getPubKey(alias: string) {

}

export type BiometricsSupport = {
    available: boolean, 
    enrolled: boolean, 
    type: 'FaceID' | 'TouchID' | 'Biometrics' | 'None' 
}

export function getBiometricSupport(): BiometricsSupport {
    
}

export function attestKey(alias: string) {

}

export function isHardwareBacked(alias: string) {

}

