import { NativeModule, requireNativeModule } from 'expo';

import { ReactNativeSiliconModuleEvents } from './types';
import { GenerateKeyOpts } from './core/keys/types';
import { BridgeResult } from './types/bridge-result';
import { SignOpts } from './core/operations/types';

declare class ReactNativeSiliconModule extends NativeModule<ReactNativeSiliconModuleEvents> {
  genKey(alias: string, opts: GenerateKeyOpts): Promise<BridgeResult<string>>;
  deleteKey(alias: string): Promise<BridgeResult<boolean>>;
  deleteAllKeys(prefix?: string): Promise<BridgeResult<number>>;
  sign(alias: string, algorithm: string | Uint8Array, opts: SignOpts): Promise<BridgeResult<string>>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ReactNativeSiliconModule>('ReactNativeSilicon');
