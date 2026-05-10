package co.alephnull.reactnative.silicon

import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.os.Build
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class ReactNativeSiliconModule : Module() {
  private val keystoreManager by lazy { SiliconKeystoreManager(appContext) }

  // Each module class must implement the definition function. The definition consists of components
  // that describes the module's functionality and behavior.
  // See https://docs.expo.dev/modules/module-api for more details about available components.
  override fun definition() = ModuleDefinition {
    // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
    // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
    // The module will be accessible from `requireNativeModule('ReactNativeSilicon')` in JavaScript.
    Name("ReactNativeSilicon")

    // Defines constant property on the module.
    Constant("PI") {
      Math.PI
    }

    // Defines event names that the module can send to JavaScript.
    Events("onChange")

    // Defines a JavaScript synchronous function that runs the native code on the JavaScript thread.
    Function("hello") {
      "Hello world! 👋"
    }

    // Defines a JavaScript function that always returns a Promise and whose native code
    // is by default dispatched on the different thread than the JavaScript runtime runs on.
    AsyncFunction("setValueAsync") { value: String ->
      // Send an event to JavaScript.
      sendEvent("onChange", mapOf(
        "value" to value
      ))
    }

    AsyncFunction("getCapabilities") {
      val packageManager = appContext.reactContext?.packageManager
      val biometricManager = BiometricManager.from(appContext.reactContext!!)

      // Check for StrongBox (The dedicated security chip)
      val hasStrongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        packageManager?.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYMASTER) ?: false
      } else {
        false
      }

      // Check for TEE (Trusted Execution Environment / Hardware isolation)
      // Almost all devices since Android 6.0 have this, but we verify it via the feature flag
      val hasHardwareKeystore = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        packageManager?.hasSystemFeature(PackageManager.FEATURE_HARDWARE_KEYSTORE) ?: true
      } else {
        // Fallback for older but still compatible versions
        true
      }

      // Check Biometric status
      val biometricStatus = biometricManager.canAuthenticate(BIOMETRIC_STRONG)
      val hasBiometrics = biometricStatus == BiometricManager.BIOMETRIC_SUCCESS

      // Return as a Map (which becomes a JS Object)
      return@AsyncFunction mapOf(
        "hasStrongBox" to hasStrongBox,
        "hasHardwareIsolation" to hasHardwareKeystore,
        "hasBiometrics" to hasBiometrics,
        "hasAttest" to (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N),
        "securityLevel" to if (hasStrongBox) "STRONGBOX" else if (hasHardwareKeystore) "TEE" else "SOFTWARE"
      )
    }

    AsyncFunction("genES256Key") { opts: GenerateKeyOptions ->
      return@AsyncFunction keystoreManager.genKey(opts).toBridgeMap()
    }
  }
}
