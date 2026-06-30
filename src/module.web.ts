import { registerWebModule, NativeModule } from 'expo';
import { GenerateKeyOpts} from './core/keys/types';
import { SiliconError, SiliconErrorCode } from './errors';
import { SignOpts } from './core/operations/types';
import { BridgeVerifyOpts } from './core/operations/brige-types';
import { RandomBytesFormat } from './core/random-generator';

/* eslint-disable @typescript-eslint/no-unused-vars */
class ReactNativeSiliconModule extends NativeModule {
  public async getCapabilities(): Promise<undefined> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async genKey(alias: string, opts: GenerateKeyOpts): Promise<undefined> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async deleteKey(alias: string): Promise<undefined> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async deleteAllKeys(prefix?: string): Promise<undefined> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async keyExists(alias: string): Promise<undefined> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async listKeys(prefix?: string): Promise<undefined> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async getPubKey(alias: string, format: 'PEM' | 'B64'): Promise<undefined> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async attestKey(alias: string): Promise<undefined> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async getKeyInfo(alias: string): Promise<undefined> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }

  public async validateKey(alias: string): Promise<undefined> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }

  public async sign(alias: string, payload: string | Uint8Array, opts: SignOpts): Promise<undefined> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }

  public async verify(payload: string | Uint8Array, signature: string, opts: BridgeVerifyOpts): Promise<undefined> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }

  public async generateSecureRandomBytes<T extends RandomBytesFormat>(length: number, format: T): Promise<undefined>  {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
  
  public async getJwk(alias: string): Promise<undefined>  {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
}

export default registerWebModule(ReactNativeSiliconModule, 'ReactNativeSiliconModule');
