import { NativeModule, requireNativeModule } from 'expo';

import { ReactNativeSiliconModuleEvents } from './types';
import { GenerateKeyOpts } from './core/keys/types';

declare class ReactNativeSiliconModule extends NativeModule<ReactNativeSiliconModuleEvents> {
  genKey(alias: string, opts: GenerateKeyOpts): Promise<string>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ReactNativeSiliconModule>('ReactNativeSilicon');
