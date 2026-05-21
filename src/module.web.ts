import { registerWebModule, NativeModule } from 'expo';
import { AttestResult, GenerateKeyOpts, KeyInfo } from './core/keys/types';
import { SiliconError, SiliconErrorCode } from './errors';
import { BridgeResult } from './types/bridge-result';
import { SignOpts } from './core/operations/types';
import { BridgeVerifyOpts } from './core/operations/brige-types';
import { Capabilities } from './core/device';
import { RandomBytesFormat, RandomGenFormatTypeMap } from './core/random-generator';

/* eslint-disable @typescript-eslint/no-unused-vars */
class ReactNativeSiliconModule extends NativeModule {
  public async getCapabilities(): Promise<BridgeResult<Capabilities>> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async genKey(alias: string, opts: GenerateKeyOpts): Promise<BridgeResult<string>> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async deleteKey(alias: string): Promise<BridgeResult<boolean>> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async deleteAllKeys(prefix?: string): Promise<BridgeResult<number>> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async keyExists(alias: string): Promise<BridgeResult<boolean>> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async listKeys(prefix?: string): Promise<BridgeResult<string[]>> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async getPubKey(alias: string, format: 'PEM' | 'B64'): Promise<BridgeResult<string>> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async attestKey(alias: string): Promise<BridgeResult<AttestResult>> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async getKeyInfo(alias: string): Promise<BridgeResult<KeyInfo>> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }

  public async validateKey(alias: string): Promise<BridgeResult<'VALID' | 'MISSING' | 'INVALIDATED' | 'UNRECOVERABLE'>> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }

  public async sign(alias: string, payload: string | Uint8Array, opts: SignOpts): Promise<BridgeResult<string>> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }

  public async verify(payload: string | Uint8Array, signature: string, opts: BridgeVerifyOpts): Promise<BridgeResult<boolean>> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }

  public async generateSecureRandomBytes<T extends RandomBytesFormat>(length: number, format: T): Promise<BridgeResult<RandomGenFormatTypeMap[T]>>  {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async getJwk(alias: string): Promise<BridgeResult<Record<string, unknown>>>  {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
}

export default registerWebModule(ReactNativeSiliconModule, 'ReactNativeSiliconModule');
