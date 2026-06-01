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
        
        AsyncFunction("listKeys") { (prefix: String?) -> [String: Any] in
            return SiliconKeystoreManager.listKeys(prefix: prefix).toBridgeMap()
        }
        
        AsyncFunction("getPubKey") { (alias: String, format: PubKeyFormat) -> [String: Any] in
            return SiliconKeystoreManager.getPubKey(alias: alias, format: format).toBridgeMap()
        }
        
        AsyncFunction("attestKey") { (alias: String, pubKeyFormat: PubKeyFormat) -> [String: Any] in
            return SiliconKeystoreManager.attestKey(alias: alias, pubKeyFormat: pubKeyFormat).toBridgeMap()
        }
        
        AsyncFunction("getKeyInfo") { (alias: String) -> [String: Any] in
            return SiliconKeystoreManager.getKeyInfo(alias: alias).toBridgeMap()
        }
        
        AsyncFunction("validateKey") { (alias: String) -> [String: Any] in
            return SiliconKeystoreManager.validateKey(alias: alias).toBridgeMap()
        }
        
        // ---- Sign/Verify ----
        
        AsyncFunction("sign") { (alias: String, payloadStr: String?, payloadByteArr: Data?, opts: SignOptions) -> [String: Any] in
            // Convert the payload to PayloadType
            let bridgePayload = BridgePayloadRecord()
            bridgePayload.text = payloadStr
            bridgePayload.bytes = payloadByteArr
            let payload = try bridgePayload.toPayloadType()
            
            return try await SiliconSigner.sign(alias: alias, payload: payload, opts: opts).toBridgeMap()
        }
        
        AsyncFunction("verify") { (payloadStr: String?, payloadByteArr: Data?, signature: String, opts: VerifyOptions) -> [String: Any] in
            // Convert the payload to PayloadType
            let bridgePayload = BridgePayloadRecord()
            bridgePayload.text = payloadStr
            bridgePayload.bytes = payloadByteArr
            let payload = try bridgePayload.toPayloadType()
            
            return try SiliconVerifier.verify(payload: payload, signatureB64: signature, opts: opts).toBridgeMap()
        }
        
        // ---- Random Generator ----
        
        AsyncFunction("generateSecureRandomBytes") { (length: Int, format: RandomBytesFormat) -> [String: Any] in
            return SiliconRandomGen.generate(length: length, format: format).toBridgeMap()
        }

        // ---- JOSE ----
        
        AsyncFunction("getJwk") { (alias: String) -> [String: Any] in
            return SiliconJose.getJwk(alias: alias).toBridgeMap()
        }
    }
}
