package co.alephnull.reactnative.silicon

import co.alephnull.reactnative.silicon.device.SiliconDevice
import co.alephnull.reactnative.silicon.helpers.SiliconHelpers
import co.alephnull.reactnative.silicon.jose.SiliconJose
import co.alephnull.reactnative.silicon.keystoremanager.AttestFormat
import co.alephnull.reactnative.silicon.keystoremanager.GenerateKeyOptions
import co.alephnull.reactnative.silicon.keystoremanager.PubkeyFormat
import co.alephnull.reactnative.silicon.keystoremanager.SiliconKSM
import co.alephnull.reactnative.silicon.randomgen.RandomBytesFormat
import co.alephnull.reactnative.silicon.randomgen.SiliconRandomGen
import co.alephnull.reactnative.silicon.signer.SignDigest
import co.alephnull.reactnative.silicon.signer.SignOptions
import co.alephnull.reactnative.silicon.signer.SiliconSigner
import co.alephnull.reactnative.silicon.verifier.SiliconVerifier
import co.alephnull.reactnative.silicon.verifier.BridgeVerifyOptions
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

    private val helpers by lazy { SiliconHelpers() }
    private val device by lazy { SiliconDevice(appContext) }
    private val keystoreManager by lazy { SiliconKSM(appContext, keystore, helpers) }
    private val signer by lazy { SiliconSigner(appContext, keystore, helpers) }
    private val verifier by lazy { SiliconVerifier(keystore) }
    private val randomGen by lazy { SiliconRandomGen() }
    private val jose by lazy { SiliconJose(keystore, helpers) }

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

        AsyncFunction("generateKey") { alias: String, opts: GenerateKeyOptions, attestChallenge: ByteArray ->
            // Uint8Array (TS) fails to map to ByteArray correctly when it is nested inside the options
            // so we extract it out of the options on the TS side and then inject it back in here
            opts.attestChallenge = attestChallenge

            val result = keystoreManager.generateKey(alias, opts)
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

        AsyncFunction("getPubKey") { alias: String, format: PubkeyFormat ->
            val result = keystoreManager.getPubKey(alias, format)
            return@AsyncFunction result.toBridgeMap()
        }

        // We ignore pubKeyFormat (ios only)
        AsyncFunction("attestKey") { alias: String, format: AttestFormat, pubKeyFormat: String ->
            val result = keystoreManager.attestKey(alias, format)
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

        AsyncFunction("sign") Coroutine { alias: String, payloadStr: String?, payloadByteArr: ByteArray?, opts: SignOptions ->
            val bridgePayload = BridgePayloadRecord()
            bridgePayload.text = payloadStr
            bridgePayload.bytes = payloadByteArr

            val result = signer.sign(alias, bridgePayload.toPayloadType(), opts)
            return@Coroutine result.toBridgeMap()
        }

        AsyncFunction("verify") {
            payloadStr: String?,
            payloadByteArr: ByteArray?,
            signatureStr: String?,
            signatureByteArr: ByteArray?,
            pubkeyStr: String?,
            pubkeyByteArr: ByteArray?,
            bridgeOpts: BridgeVerifyOptions ->

            // Pack payload into PayloadType
            val bridgePayload = BridgePayloadRecord()
            bridgePayload.text = payloadStr
            bridgePayload.bytes = payloadByteArr

            // Pack signature into PayloadType
            val bridgeSignature = BridgePayloadRecord()
            bridgeSignature.text = signatureStr
            bridgeSignature.bytes = signatureByteArr

            // Pack pubkeyStr and pubkeyBytes into PayloadType
            var pubkey: BridgePayloadRecord? = null
            if (pubkeyStr != null || pubkeyByteArr != null) {
                pubkey = BridgePayloadRecord()
                pubkey.text = pubkeyStr
                pubkey.bytes = pubkeyByteArr
            }

            // Populate VerifyOptions
            val opts = VerifyOptions()
            opts.pubkey = when (pubkey) {
                null -> null
                else -> pubkey.toPayloadType()
            }
            opts.alias = bridgeOpts.alias
            opts.algorithm = bridgeOpts.algorithm

            val result = verifier.verify(
                bridgePayload.toPayloadType(),
                bridgeSignature.toPayloadType(),
                opts
            )
            return@AsyncFunction result.toBridgeMap()
        }

        // ---- Random Generator ----

        AsyncFunction("generateSecureRandomBytes") { length: Int, format: RandomBytesFormat ->
            val result = randomGen.generate(length, format)
            return@AsyncFunction result.toBridgeMap()
        }

        // ---- JOSE ----

        AsyncFunction("getJwk") { alias: String ->
            val result = jose.getJwk(alias)
            return@AsyncFunction result.toBridgeMap()
        }
    }
}
