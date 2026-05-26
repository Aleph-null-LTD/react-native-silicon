import ExpoModulesCore

public class ReactNativeSiliconModule: Module {
    // Each module class must implement the definition function. The definition consists of components
    // that describes the module's functionality and behavior.
    // See https://docs.expo.dev/modules/module-api for more details about available components.
    public func definition() -> ModuleDefinition {
        // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
        // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
        // The module will be accessible from `requireNativeModule('ReactNativeSilicon')` in JavaScript.
        Name("ReactNativeSilicon")

        AsyncFunction("getCapabilities") { () -> [String: Any] in
            return SiliconDevice.getCapabilities().toBridgeMap()
        }
          
        // ---- Keystore Manager ----
        
        AsyncFunction("generateKey") { (alias: String, opts: GenerateKeyOptions) -> [String: Any] in
            return try SiliconKeystoreManager.generateKey(alias: alias, opts: opts).toBridgeMap()
        }
        
        AsyncFunction("deleteKey") { (alias: String) -> [String: Any] in
            return SiliconKeystoreManager.deleteKey(alias: alias).toBridgeMap()
        }
        
        AsyncFunction("deleteAllKeys") { (prefix: String?) -> [String: Any] in
            return SiliconKeystoreManager.deleteAllKeys(prefix: prefix).toBridgeMap()
        }
        
        AsyncFunction("keyExists") { (alias: String) -> [String: Any] in
            return SiliconKeystoreManager.keyExists(alias: alias).toBridgeMap()
        }
        
        AsyncFunction("listKeys") { (alias: prefix: String?) -> [String: Any] in
            return SiliconKeystoreManager.listKeys(prefix: prefix).toBridgeMap()
        }
        
        // ---- Random Generator ----
        
        AsyncFunction("generateSecureRandomBytes") { (length: Int, format: RandomBytesFormat) -> [String: Any] in
            return SiliconRandomGen.generate(length: length, format: format).toBridgeMap()
        }

        /*

        AsyncFunction("listKeys") { (prefix: String?) in
            val result = keystoreManager.listKeys(prefix)
            return@AsyncFunction result.toBridgeMap()
        }

        AsyncFunction("getPubKey") { (alias: String, format: PubkeyFormat) in
            val result = keystoreManager.getPubKey(alias, format)
            return@AsyncFunction result.toBridgeMap()
        }

        AsyncFunction("attestKey") { (alias: String) in
            val result = keystoreManager.attestKey(alias)
            return@AsyncFunction result.toBridgeMap()
        }

        AsyncFunction("getKeyInfo") { (alias: String) in
            val result = keystoreManager.getKeyInfo(alias)
            return@AsyncFunction result.toBridgeMap()
        }

        AsyncFunction("validateKey") { (alias: String) in
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

        AsyncFunction("verify") { payloadStr: String?, payloadByteArr: ByteArray?, signatureB64: String, opts: VerifyOptions ->
            val bridgePayload = BridgePayloadRecord()
            bridgePayload.text = payloadStr
            bridgePayload.bytes = payloadByteArr

            val result = verifier.verify(bridgePayload.toPayloadType(), signatureB64, opts)
            return@AsyncFunction result.toBridgeMap()
        }

        // ---- JOSE ----

        AsyncFunction("getJwk") { alias: String ->
            val result = jose.getJwk(alias)
            return@AsyncFunction result.toBridgeMap()
        }
        */
    }
}
