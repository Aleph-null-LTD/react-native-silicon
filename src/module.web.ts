import { registerWebModule, NativeModule } from 'expo';

import { ReactNativeSiliconModuleEvents } from './types';

class ReactNativeSiliconModule extends NativeModule<ReactNativeSiliconModuleEvents> {
  PI = Math.PI;
  async setValueAsync(value: string): Promise<void> {
    this.emit('onChange', { value });
  }
  hello() {
    return 'Hello world! 👋';
  }
}

export default registerWebModule(ReactNativeSiliconModule, 'ReactNativeSiliconModule');
