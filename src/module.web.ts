import { registerWebModule, NativeModule } from 'expo';

import { ReactNativeSiliconModuleEvents } from './types';
import { GenerateKeyOpts } from './core/keys/types';
import { SiliconError, SiliconErrorCode } from './errors';

class ReactNativeSiliconModule extends NativeModule<ReactNativeSiliconModuleEvents> {
  public async genES256Key(opts: GenerateKeyOpts): Promise<string> {
    throw new SiliconError(SiliconErrorCode.PLATFORM_NOT_SUPPORTED, "This feature is not available for web");
  }
}

export default registerWebModule(ReactNativeSiliconModule, 'ReactNativeSiliconModule');
