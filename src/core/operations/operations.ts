import { SiliconError, SiliconErrorCode } from '../../errors';
import NativeSilicon from '../../module';
import { SignOpts } from './types';

// -- Raw Sign & Verify --

export async function sign(alias: string, payload: string | Uint8Array, opts: SignOpts): Promise<string> {
    const result = await NativeSilicon.sign(alias, payload, opts);
    if (!result.success) {
        switch (result.errorCode) {
            case 'KEY_NOT_FOUND':
                throw new SiliconError(SiliconErrorCode.KEY_NOT_FOUND, result.errorMessage);

            case 'KEY_INVALIDATED':
                throw new SiliconError(SiliconErrorCode.KEY_INVALIDATED, result.errorMessage);

            case 'UNSUPPORTED_KEY_FAMILY':
                throw new SiliconError(SiliconErrorCode.UNSUPPORTED_KEY_FAMILY, result.errorMessage);

            case 'SIGNING_FAILED':
            case 'PROMPT_SIGN_FAILED':
                throw new SiliconError(SiliconErrorCode.SIGNING_FAILED, result.errorMessage);
            
            default:
                throw new SiliconError(SiliconErrorCode.UNKNOWN_NATIVE_ERROR, `${result.errorCode}: ${result.errorMessage}`);
        }
    }

    return result.data;
}

export function verify(payload, signature, publicKey) {

}

// -- Hardware-Backed Symmetric Encryption --

export function encrypt(alias: string, data) {

}

export function decrypt(alias: string, cipherText) {
    
}

