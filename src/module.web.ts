import { registerWebModule, NativeModule } from 'expo';

import { ReactNativeSiliconModuleEvents } from './types';
import { GenerateKeyOpts, KeyInfo } from './core/keys/types';
import { SiliconError, SiliconErrorCode } from './errors';
import { BridgeResult } from './types/bridge-result';
import { BridgeVerifyOpts, SignOpts } from './core/operations/types';

class ReactNativeSiliconModule extends NativeModule<ReactNativeSiliconModuleEvents> {
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
  
  public async attestKey(alias: string): Promise<BridgeResult<string[]>> {
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
}

export default registerWebModule(ReactNativeSiliconModule, 'ReactNativeSiliconModule');
