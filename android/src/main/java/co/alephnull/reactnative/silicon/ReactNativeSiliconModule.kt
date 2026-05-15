package co.alephnull.reactnative.silicon

import co.alephnull.reactnative.silicon.device.SiliconDevice
import co.alephnull.reactnative.silicon.keystoremanager.GenerateKeyOptions
import co.alephnull.reactnative.silicon.keystoremanager.PubkeyFormat
import co.alephnull.reactnative.silicon.keystoremanager.SiliconKeystoreManager
import co.alephnull.reactnative.silicon.randomgen.RandomBytesFormat
import co.alephnull.reactnative.silicon.randomgen.SiliconRandomGen
import co.alephnull.reactnative.silicon.signer.SignOptions
import co.alephnull.reactnative.silicon.signer.SiliconSigner
import co.alephnull.reactnative.silicon.verifier.SiliconVerifier
import co.alephnull.reactnative.silicon.verifier.VerifyOptions
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

  private val device by lazy { SiliconDevice(appContext) }
  private val keystoreManager by lazy { SiliconKeystoreManager(appContext, keystore) }
  private val signer by lazy { SiliconSigner(appContext, keystore) }
  private val verifier by lazy { SiliconVerifier(keystore) }
  private val randomGen by lazy { SiliconRandomGen() }

  // Each module class must implement the definition function. The definition consists of components
  // that describes the module's functionality and behavior.
  // See https://docs.expo.dev/modules/module-api for more details about available components.
  override fun definition() = ModuleDefinition {
    // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
    // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
    // The module will be accessible from `requireNativeModule('ReactNativeSilicon')` in JavaScript.
    Name("ReactNativeSilicon")

    AsyncFunction("getCapabilities") {
      val result = device.getCapabilities()
      return@AsyncFunction result.toBridgeMap()
    }

    // ---- Keystore Manager ----

    AsyncFunction("genKey") { alias: String, opts: GenerateKeyOptions ->
      val result = keystoreManager.genKey(alias, opts)
      return@AsyncFunction result.toBridgeMap()
    }

    AsyncFunction("deleteKey") { alias: String ->
      val result = keystoreManager.deleteKey(alias)
      return@AsyncFunction result.toBridgeMap()
    }

    AsyncFunction("deleteAllKeys") { prefix: String? ->
      val result = keystoreManager.deleteAllKeys(prefix)
      return@AsyncFunction result.toBridgeMap()
    }

    AsyncFunction("keyExists") { alias: String ->
      val result = keystoreManager.keyExists(alias)
      return@AsyncFunction result.toBridgeMap()
    }

    AsyncFunction("listKeys") { prefix: String? ->
      val result = keystoreManager.listKeys(prefix)
      return@AsyncFunction result.toBridgeMap()
    }

    AsyncFunction("getPubkey") { alias: String, format: PubkeyFormat ->
      val result = keystoreManager.getPubKey(alias, format)
      return@AsyncFunction result.toBridgeMap()
    }

    AsyncFunction("attestKey") { alias: String ->
      val result = keystoreManager.attestKey(alias)
      return@AsyncFunction result.toBridgeMap()
    }

    AsyncFunction("getKeyInfo") { alias: String ->
      val result = keystoreManager.getKeyInfo(alias)
      return@AsyncFunction result.toBridgeMap()
    }

    AsyncFunction("validateKey") { alias: String ->
      val result = keystoreManager.validateKey(alias)
      return@AsyncFunction result.toBridgeMap()
    }

    // ---- Sign/Verify ----

    AsyncFunction("sign") Coroutine { alias: String, payload: BridgePayloadRecord, opts: SignOptions ->
      val result = signer.sign(alias, payload.toPayloadType(), opts)
      return@Coroutine result.toBridgeMap()
    }

    AsyncFunction("verify") { payload: BridgePayloadRecord, signatureB64: String, opts: VerifyOptions ->
      val result = verifier.verify(payload.toPayloadType(), signatureB64, opts)
      return@AsyncFunction result.toBridgeMap()
    }

    // ---- Random Generator ----

    AsyncFunction("generateSecureRandomBytes") { length: Int, format: RandomBytesFormat ->
      val result = randomGen.generate(length, format)
      return@AsyncFunction result.toBridgeMap()
    }

  }
}
