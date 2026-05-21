import { NativeModule, requireNativeModule } from 'expo';
import { AttestResult, GenerateKeyOpts, KeyInfo } from './core/keys/types';
import { BridgeResult } from './types/bridge-result';
import { SignOpts } from './core/operations/types';
import { BridgeVerifyOpts } from './core/operations/brige-types';
import { Capabilities } from './core/device/types';
import { RandomBytesFormat, RandomGenFormatTypeMap } from './core/random-generator/types';

declare class ReactNativeSiliconModule extends NativeModule {
  getCapabilities(): Promise<BridgeResult<Capabilities>>;
  genKey(alias: string, opts: GenerateKeyOpts): Promise<BridgeResult<string>>;
  deleteKey(alias: string): Promise<BridgeResult<boolean>>;
  deleteAllKeys(prefix?: string): Promise<BridgeResult<number>>;
  keyExists(alias: string): Promise<BridgeResult<boolean>>;
  listKeys(prefix?: string): Promise<BridgeResult<string[]>>;
  getPubKey(alias: string, format: 'PEM' | 'B64'): Promise<BridgeResult<string>>;
  attestKey(alias: string): Promise<BridgeResult<AttestResult>>;
  getKeyInfo(alias: string): Promise<BridgeResult<KeyInfo>>;
  validateKey(alias: string): Promise<BridgeResult<'VALID' | 'MISSING' | 'INVALIDATED' | 'UNRECOVERABLE'>>;
  sign(alias: string, payloadStr: string | null, payloadByteArr: Uint8Array | null, opts: SignOpts): Promise<BridgeResult<string>>;
  verify(payloadStr: string | null, payloadByteArr: Uint8Array | null, signature: string, opts: BridgeVerifyOpts): Promise<BridgeResult<boolean>>;
  generateSecureRandomBytes<T extends RandomBytesFormat>(length: number, format: T): Promise<BridgeResult<RandomGenFormatTypeMap[T]>>;
  getJwk(alias: string): Promise<BridgeResult<Record<string, unknown>>>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ReactNativeSiliconModule>('ReactNativeSilicon');
