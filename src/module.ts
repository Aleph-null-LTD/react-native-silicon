import { NativeModule, requireNativeModule } from 'expo';
import { AttestFormats, AttestResult, GenerateKeyOpts, KeyInfo, PubkeyFormat, PubKeyFormatTypeMap } from './core/keys/types';
import { BridgeResult } from './types/bridge-result';
import { SignDigest, SignEncodings, SignEncodingsTypeMap, SignOpts } from './core/operations/types';
import { BridgeVerifyOpts } from './core/operations/brige-types';
import { Capabilities } from './core/device/types';
import { RandomBytesFormat, RandomGenFormatTypeMap } from './core/random-generator/types';

declare class ReactNativeSiliconModule extends NativeModule {
  getCapabilities(): Promise<BridgeResult<Capabilities>>;
  generateKey(alias: string, opts: GenerateKeyOpts, attestChallenge: Uint8Array | undefined): Promise<BridgeResult<undefined>>;
  deleteKey(alias: string): Promise<BridgeResult<boolean>>;
  deleteAllKeys(prefix?: string): Promise<BridgeResult<number>>;
  keyExists(alias: string): Promise<BridgeResult<boolean>>;
  listKeys(prefix?: string): Promise<BridgeResult<string[]>>;
  getPubKey<F extends PubkeyFormat>(alias: string, format: F): Promise<BridgeResult<PubKeyFormatTypeMap[F]>>;
  attestKey<F extends AttestFormats, P extends PubkeyFormat>(alias: string, format: F, pubKeyFormat: P): Promise<BridgeResult<AttestResult<F, P>>>;
  getKeyInfo(alias: string): Promise<BridgeResult<KeyInfo>>;
  validateKey(alias: string): Promise<BridgeResult<'VALID' | 'MISSING' | 'INVALIDATED' | 'UNRECOVERABLE'>>;
  sign<F extends SignEncodings = 'BYTES'>(alias: string, payloadStr: string | null, payloadByteArr: Uint8Array | null, opts?: SignOpts<F>): Promise<BridgeResult<SignEncodingsTypeMap[F]>>;
  verify(payloadStr: string | null, payloadByteArr: Uint8Array | null, signatureStr: string | null, signatureByteArr: Uint8Array | null, bridgeOpts: BridgeVerifyOpts): Promise<BridgeResult<boolean>>;
  generateSecureRandomBytes<T extends RandomBytesFormat>(length: number, format: T): Promise<BridgeResult<RandomGenFormatTypeMap[T]>>;
  getJwk(alias: string, digest?: SignDigest): Promise<BridgeResult<Record<string, unknown>>>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ReactNativeSiliconModule>('ReactNativeSilicon');
