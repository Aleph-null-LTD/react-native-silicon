package co.alephnull.reactnative.silicon

import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.os.Build
import co.alephnull.reactnative.silicon.keystoremanager.GenerateKeyOptions
import co.alephnull.reactnative.silicon.keystoremanager.SiliconKeystoreManager
import co.alephnull.reactnative.silicon.signer.PayloadType
import co.alephnull.reactnative.silicon.signer.SignOptions
import co.alephnull.reactnative.silicon.signer.SiliconSigner
import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.security.KeyStore

class ReactNativeSiliconModule : Module() {
  private val keystore by lazy {
    // Instantiate the keystore
    // We pass in "AndroidKeyStore", and pass 'null' into load (Android OS manages the hardware-level storage automatically)
    KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  }

  private val keystoreManager by lazy { SiliconKeystoreManager(appContext, keystore) }
  private val signer by lazy { SiliconSigner(appContext, keystore) }

  // Each module class must implement the definition function. The definition consists of components
  // that describes the module's functionality and behavior.
  // See https://docs.expo.dev/modules/module-api for more details about available components.
  override fun definition() = ModuleDefinition {
    // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
    // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
    // The module will be accessible from `requireNativeModule('ReactNativeSilicon')` in JavaScript.
    Name("ReactNativeSilicon")

    // Defines constant property on the module.
    /*
    Constant("PI") {
      Math.PI
    }
    */

    // Defines event names that the module can send to JavaScript.
    //Events("onChange")

    // Defines a JavaScript synchronous function that runs the native code on the JavaScript thread.
    /*
    Function("hello") {
      "Hello world! 👋"
    }
    */

    // Defines a JavaScript function that always returns a Promise and whose native code
    // is by default dispatched on the different thread than the JavaScript runtime runs on.
    /*
    AsyncFunction("setValueAsync") { value: String ->
      // Send an event to JavaScript.
      sendEvent("onChange", mapOf(
        "value" to value
      ))
    }
    */

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

    AsyncFunction("genKey") { alias: String, opts: GenerateKeyOptions ->
      val result = keystoreManager.genKey(alias, opts)
      return@AsyncFunction result.toBridgeMap()
    }

    AsyncFunction("deleteKey") { alias: String ->
      val result = keystoreManager.deleteKey(alias)
      return@AsyncFunction result.toBridgeMap()
    }

    AsyncFunction("deleteAllKeys") { prefix: String ->
      val result = keystoreManager.deleteAllKeys(prefix)
      return@AsyncFunction result.toBridgeMap()
    }

    AsyncFunction("sign") Coroutine { alias: String, payload: PayloadType, opts: SignOptions ->
      val result = signer.sign(alias, payload, opts)
      return@Coroutine result.toBridgeMap()
    }
  }
}
