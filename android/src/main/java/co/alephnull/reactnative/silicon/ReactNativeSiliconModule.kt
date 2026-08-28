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
            try {
                val result = device.getCapabilities()
                return@AsyncFunction result.toBridgeMap()
            } catch (e: Exception) {
                return@AsyncFunction SiliconResult.Failure(
                    SiliconErrorCode.GET_CAPABILITIES_FAILED,
                    e.localizedMessage ?: "Failed to due to unexpected error"
                ).toBridgeMap()
            }
        }

        // ---- Keystore Manager ----

        AsyncFunction("generateKey") { alias: String, opts: GenerateKeyOptions, attestChallenge: ByteArray ->
            try {
                // Uint8Array (TS) fails to map to ByteArray correctly when it is nested inside the options
                // so we extract it out of the options on the TS side and then inject it back in here
                opts.attestChallenge = attestChallenge

                val result = keystoreManager.generateKey(alias, opts)
                return@AsyncFunction result.toBridgeMap()
            } catch (e: Exception) {
                return@AsyncFunction SiliconResult.Failure(
                    SiliconErrorCode.GENERATE_KEY_FAILED,
                    e.localizedMessage ?: "Failed to due to unexpected error"
                ).toBridgeMap()
            }
        }

        AsyncFunction("deleteKey") { alias: String ->
            try {
                val result = keystoreManager.deleteKey(alias)
                return@AsyncFunction result.toBridgeMap()
            } catch (e: Exception) {
                return@AsyncFunction SiliconResult.Failure(
                    SiliconErrorCode.DELETE_FAILED,
                    e.localizedMessage ?: "Failed to due to unexpected error"
                ).toBridgeMap()
            }
        }

        AsyncFunction("deleteAllKeys") { prefix: String? ->
            try {
                val result = keystoreManager.deleteAllKeys(prefix)
                return@AsyncFunction result.toBridgeMap()
            } catch (e: Exception) {
                return@AsyncFunction SiliconResult.Failure(
                    SiliconErrorCode.DELETE_ALL_FAILED,
                    e.localizedMessage ?: "Failed to due to unexpected error"
                ).toBridgeMap()
            }
        }

        AsyncFunction("keyExists") { alias: String ->
            try {
                val result = keystoreManager.keyExists(alias)
                return@AsyncFunction result.toBridgeMap()
            } catch (e: Exception) {
                return@AsyncFunction SiliconResult.Failure(
                    SiliconErrorCode.KEY_EXISTS_FAILED,
                    e.localizedMessage ?: "Failed to due to unexpected error"
                ).toBridgeMap()
            }
        }

        AsyncFunction("listKeys") { prefix: String? ->
            try {
                val result = keystoreManager.listKeys(prefix)
                return@AsyncFunction result.toBridgeMap()
            } catch (e: Exception) {
                return@AsyncFunction SiliconResult.Failure(
                    SiliconErrorCode.LIST_KEYS_FAILED,
                    e.localizedMessage ?: "Failed to due to unexpected error"
                ).toBridgeMap()
            }
        }

        AsyncFunction("getPubKey") { alias: String, format: PubkeyFormat ->
            try {
                val result = keystoreManager.getPubKey(alias, format)
                return@AsyncFunction result.toBridgeMap()
            } catch (e: Exception) {
                return@AsyncFunction SiliconResult.Failure(
                    SiliconErrorCode.GET_PUB_KEY_FAILED,
                    e.localizedMessage ?: "Failed to due to unexpected error"
                ).toBridgeMap()
            }
        }

        // We ignore pubKeyFormat (ios only)
        AsyncFunction("attestKey") { alias: String, format: AttestFormat, pubKeyFormat: String ->
            try {
                val result = keystoreManager.attestKey(alias, format)
                return@AsyncFunction result.toBridgeMap()
            } catch (e: Exception) {
                return@AsyncFunction SiliconResult.Failure(
                    SiliconErrorCode.ATTEST_KEY_FAILED,
                    e.localizedMessage ?: "Failed to due to unexpected error"
                ).toBridgeMap()
            }
        }

        AsyncFunction("getKeyInfo") { alias: String ->
            try {
                val result = keystoreManager.getKeyInfo(alias)
                return@AsyncFunction result.toBridgeMap()
            } catch (e: Exception) {
                return@AsyncFunction SiliconResult.Failure(
                    SiliconErrorCode.GET_KEY_INFO_FAILED,
                    e.localizedMessage ?: "Failed to due to unexpected error"
                ).toBridgeMap()
            }
        }

        AsyncFunction("validateKey") { alias: String ->
            try {
                val result = keystoreManager.validateKey(alias)
                return@AsyncFunction result.toBridgeMap()
            } catch (e: Exception) {
                return@AsyncFunction SiliconResult.Failure(
                    SiliconErrorCode.VALIDATE_KEY_FAILED,
                    e.localizedMessage ?: "Failed to due to unexpected error"
                ).toBridgeMap()
            }
        }

        // ---- Sign/Verify ----

        AsyncFunction("sign") Coroutine { alias: String, payloadStr: String?, payloadByteArr: ByteArray?, opts: SignOptions ->
            try {
                val bridgePayload = BridgePayloadRecord()
                bridgePayload.text = payloadStr
                bridgePayload.bytes = payloadByteArr

                val result = signer.sign(alias, bridgePayload.toPayloadType(), opts)
                return@Coroutine result.toBridgeMap()
            } catch (e: Exception) {
                return@Coroutine SiliconResult.Failure(
                    SiliconErrorCode.SIGN_FAILED,
                    e.localizedMessage ?: "Failed to due to unexpected error"
                ).toBridgeMap()
            }
        }

        AsyncFunction("verify") {
            payloadStr: String?,
            payloadByteArr: ByteArray?,
            signatureStr: String?,
            signatureByteArr: ByteArray?,
            pubkeyStr: String?,
            pubkeyByteArr: ByteArray?,
            bridgeOpts: BridgeVerifyOptions ->

            try {
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
            } catch (e: Exception) {
                return@AsyncFunction SiliconResult.Failure(
                    SiliconErrorCode.VERIFY_FAILED,
                    e.localizedMessage ?: "Failed to due to unexpected error"
                ).toBridgeMap()
            }
        }

        // ---- Random Generator ----

        AsyncFunction("generateSecureRandomBytes") { length: Int, format: RandomBytesFormat ->
            try {
                val result = randomGen.generate(length, format)
                return@AsyncFunction result.toBridgeMap()
            } catch (e: Exception) {
                return@AsyncFunction SiliconResult.Failure(
                    SiliconErrorCode.RANDOM_GEN_FAILED,
                    e.localizedMessage ?: "Failed to due to unexpected error"
                ).toBridgeMap()
            }
        }

        // ---- JOSE ----

        AsyncFunction("getJwk") { alias: String, digest: SignDigest? ->
            try {
                val result = jose.getJwk(alias, digest)
                return@AsyncFunction result.toBridgeMap()
            } catch (e: Exception) {
                return@AsyncFunction SiliconResult.Failure(
                    SiliconErrorCode.GET_JWK_FAILED,
                    e.localizedMessage ?: "Failed to due to unexpected error"
                ).toBridgeMap()
            }
        }
    }
}
