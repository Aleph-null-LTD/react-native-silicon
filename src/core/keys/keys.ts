import NativeSilicon from '../../module';
import { GenerateKeyOpts } from "./types";



export function generateKey(alias: string, opts: GenerateKeyOpts): Promise<string> {
    return NativeSilicon.genKey(alias, opts);
}

export function deleteKey(alias: string) {

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

