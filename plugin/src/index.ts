import {
  ConfigPlugin,
  createRunOncePlugin,
  withInfoPlist,
  AndroidConfig,
  withPlugins,
} from '@expo/config-plugins';

// Define the props developers can pass in their app.json
type PluginProps = {
  /**
   * The message shown to the user when FaceID is requested.
   * Default: "Allow $(PRODUCT_NAME) to securely sign cryptographic payloads."
   */
  faceIDPermission?: string;
};

/**
 * iOS Configuration
 * Injects the NSFaceIDUsageDescription into the Info.plist
 */
const withIOSFaceID: ConfigPlugin<PluginProps> = (config, props) => {
  return withInfoPlist(config, (config) => {
    // Set the FaceID message (only if it is not already defined by the consumer)
    config.modResults.NSFaceIDUsageDescription =
      config.modResults.NSFaceIDUsageDescription ||
      props.faceIDPermission ||
      'Allow $(PRODUCT_NAME) to use Face ID for secure cryptographic keys.';
    return config;
  });
};

/**
 * Android Configuration
 * Injects USE_BIOMETRIC and USE_FINGERPRINT into the AndroidManifest.xml
 */
const withAndroidBiometrics: ConfigPlugin = (config) => {
  return AndroidConfig.Permissions.withPermissions(config, [
    'android.permission.USE_BIOMETRIC',
    'android.permission.USE_FINGERPRINT', // Fallback for older Android devices
  ]);
};

/**
 * Main Plugin Wrapper
 * Chains the iOS and Android configurations together
 */
const withReactNativeSilicon: ConfigPlugin<PluginProps> = (config, props = {}) => {
  return withPlugins(config, [
    [withIOSFaceID, props],
    withAndroidBiometrics,
  ]);
};

// Export the plugin wrapped in `createRunOncePlugin`
// This ensures the plugin isn't accidentally applied multiple times during complex builds.
export default createRunOncePlugin(
  withReactNativeSilicon,
  'react-native-silicon',
);
