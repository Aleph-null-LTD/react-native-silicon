import { NativeModule, requireNativeModule } from 'expo';
import { ReactNativeSiliconModuleEvents } from './types';
import { AttestResult, GenerateKeyOpts, KeyInfo } from './core/keys/types';
import { BridgeResult } from './types/bridge-result';
import { SignOpts, BridgeVerifyOpts } from './core/operations/types';
import { Capabilities } from './core/device/types';
import { RandomBytesFormat } from './core/random-generator/types';

declare class ReactNativeSiliconModule extends NativeModule<ReactNativeSiliconModuleEvents> {
  getCapabilities(): Promise<BridgeResult<Capabilities>>;
  genKey(alias: string, opts: GenerateKeyOpts): Promise<BridgeResult<string>>;
  deleteKey(alias: string): Promise<BridgeResult<boolean>>;
  deleteAllKeys(prefix?: string): Promise<BridgeResult<number>>;
  keyExists(alias: string): Promise<BridgeResult<boolean>>;
  listKeys(prefix?: string): Promise<BridgeResult<string[]>>;
  getPubkey(alias: string, format: 'PEM' | 'B64'): Promise<BridgeResult<string>>;
  attestKey(alias: string): Promise<BridgeResult<AttestResult>>;
  getKeyInfo(alias: string): Promise<BridgeResult<KeyInfo>>;
  validateKey(alias: string): Promise<BridgeResult<'VALID' | 'MISSING' | 'INVALIDATED' | 'UNRECOVERABLE'>>;
  sign(alias: string, payload: string | Uint8Array, opts: SignOpts): Promise<BridgeResult<string>>;
  verify(payload: string | Uint8Array, signature: string, opts: BridgeVerifyOpts): Promise<BridgeResult<boolean>>;
  generateSecureRandomBytes(length: number, format: RandomBytesFormat): Promise<BridgeResult<Uint8Array | string>>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ReactNativeSiliconModule>('ReactNativeSilicon');
