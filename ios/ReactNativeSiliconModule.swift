import ExpoModulesCore

public class ReactNativeSiliconModule: Module {
    // MARK: - Providers (External dependencies)
    private lazy var attestService: AttestServiceProvider = AttestService()
    private lazy var secItems: SecItemsProvider = SecItems()
    private lazy var secKeys: SecKeysProvider = SecKeys()
    private lazy var secAccessControls: SecAccessControlsProvider = SecAccessControls()
    private lazy var secRandom: SecRandomProvider = SecRandom()
    private lazy var secureEnclave: SecureEnclaveProvider = SecureEnclave()
    private lazy var authContextSession: AuthContextSessionProvider = AuthContextSession()
    
    // MARK: - Shared (Shared core functionality)
    private lazy var authContextCache: AuthContextCache = AuthContextCache(authContextSession: authContextSession)
    private lazy var keychainHelper: KeychainHelping = KeychainHelper(secItems: secItems)
    private lazy var keyMetadataStore: KeyMetadataStoring = KeyMetadataStore(keychainHelper: keychainHelper)
    private lazy var pubKeyData: PubKeyData = PubKeyData(secItems: secItems, secKeys: secKeys)
    
    // MARK: - Handlers (Handling bridge requests)
    private lazy var siliconDevice: SiliconDevice = SiliconDevice(
        authContextSession: authContextSession,
        secureEnclave: secureEnclave,
        attestService: attestService
    )
    
    private lazy var keyGenerator: KeyGenerating = KeyGenerator(
        attestService: attestService,
        secItems: secItems,
        secKeys: secKeys,
        secAccessControls: secAccessControls,
        keychainHelper: keychainHelper
    )
    private lazy var siliconKSM = SiliconKeystoreManager(
        attestService: attestService,
        secItems: secItems,
        secAccessControls: secAccessControls,
        secureEnclave: secureEnclave,
        authContextSession: authContextSession,
        pubKeyData: pubKeyData,
        keyGenerator: keyGenerator,
        keychainHelper: keychainHelper,
        keyMetadataStore: keyMetadataStore
    )
    
    private lazy var siliconSigner = SiliconSigner(authContextCache: authContextCache, keyMetadataStore: keyMetadataStore)
    
    private lazy var siliconVerifier = SiliconVerifier(secItems: secItems, secKeys: secKeys, keyMetadataStore: keyMetadataStore)
    
    private lazy var siliconJose = SiliconJose(keyMetadataStore: keyMetadataStore, pubKeyData: pubKeyData)
    
    private lazy var siliconRandomGen = SiliconRandomGen(secRandom: secRandom)
    
    // MARK: - Definition
    // Each module class must implement the definition function. The definition consists of components
    // that describes the module's functionality and behavior.
    // See https://docs.expo.dev/modules/module-api for more details about available components.
    public func definition() -> ModuleDefinition {
        // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
        // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
        // The module will be accessible from `requireNativeModule('ReactNativeSilicon')` in JavaScript.
        Name("ReactNativeSilicon")

        // ---- Device ----
        
        AsyncFunction("getCapabilities") { () -> [String: Any] in
            return siliconDevice.getCapabilities().toBridgeMap()
        }
          
        // ---- Keystore Manager ----
        
        AsyncFunction("generateKey") { (alias: String, opts: GenerateKeyOptions, attestChallenge: Data?) -> [String: Any] in
            // Uint8Array (TS) fails to map to Data correctly when it is nested inside the options
            // so we extract it out of the options on the TS side and then inject it back in here
            opts.attestChallenge = attestChallenge
            
            return await siliconKSM.generateKey(alias: alias, opts: opts).toBridgeMap()
        }
        
        AsyncFunction("deleteKey") { (alias: String) -> [String: Any] in
            return siliconKSM.deleteKey(alias: alias).toBridgeMap()
        }
        
        AsyncFunction("deleteAllKeys") { (prefix: String?) -> [String: Any] in
            return siliconKSM.deleteAllKeys(prefix: prefix).toBridgeMap()
        }
        
        AsyncFunction("keyExists") { (alias: String) -> [String: Any] in
            return siliconKSM.keyExists(alias: alias).toBridgeMap()
        }
        
        AsyncFunction("listKeys") { (prefix: String?) -> [String: Any] in
            return siliconKSM.listKeys(prefix: prefix).toBridgeMap()
        }
        
        AsyncFunction("getPubKey") { (alias: String, format: PubKeyFormat) -> [String: Any] in
            return siliconKSM.getPubKey(alias: alias, format: format).toBridgeMap()
        }
        
        AsyncFunction("attestKey") { (alias: String, format: AttestFormat, pubKeyFormat: PubKeyFormat) -> [String: Any] in
            return await siliconKSM.attestKey(alias: alias, format: format, pubKeyFormat: pubKeyFormat).toBridgeMap()
        }
        
        AsyncFunction("getKeyInfo") { (alias: String) -> [String: Any] in
            return siliconKSM.getKeyInfo(alias: alias).toBridgeMap()
        }
        
        AsyncFunction("validateKey") { (alias: String) -> [String: Any] in
            return siliconKSM.validateKey(alias: alias).toBridgeMap()
        }
        
        // ---- Sign/Verify ----
        
        AsyncFunction("sign") { (alias: String, payloadStr: String?, payloadByteArr: Data?, opts: SignOptions) -> [String: Any] in
            do {
                // Convert the payload to PayloadType
                let bridgePayload = BridgePayloadRecord()
                bridgePayload.text = payloadStr
                bridgePayload.bytes = payloadByteArr
                let payload = try bridgePayload.toPayloadType()
                
                return await siliconSigner.sign(alias: alias, payload: payload, opts: opts).toBridgeMap()
                
            } catch {
                return SiliconResult<Never>.failure(
                    code: .INTERNAL_ERROR,
                    message: error.localizedDescription,
                    nativeStack: nil
                ).toBridgeMap()
            }
        }
        
        AsyncFunction("verify") { (
            payloadStr: String?,
            payloadByteArr: Data?,
            signatureStr: String?,
            signatureByteArr: Data?,
            bridgeOpts: BridgeVerifyOptions
        ) -> [String: Any] in
            do {
                // Pack payload into PayloadType
                let bridgePayload = BridgePayloadRecord()
                bridgePayload.text = payloadStr
                bridgePayload.bytes = payloadByteArr
                let payload = try bridgePayload.toPayloadType()
                
                // Pack signature into PayloadType
                let bridgeSignature = BridgePayloadRecord()
                bridgeSignature.text = signatureStr
                bridgeSignature.bytes = signatureByteArr
                let signature = try bridgeSignature.toPayloadType()
                
                // Pack bridgeOpts.pubkeyStr and bridgeOpts.pubkeyBytes into PayloadType
                var pubkey: PayloadType?
                if bridgeOpts.pubkeyBytes != nil || bridgeOpts.pubkeyStr != nil {
                    let bridgePubkey = BridgePayloadRecord()
                    bridgePubkey.text = bridgeOpts.pubkeyStr
                    bridgePubkey.bytes = bridgeOpts.pubkeyBytes
                    pubkey = try bridgePubkey.toPayloadType()
                }
                let opts = VerifyOptions(
                    alias: bridgeOpts.alias,
                    pubkey: pubkey,
                    algorithm: bridgeOpts.algorithm
                )
                
                return siliconVerifier.verify(payload: payload, signature: signature, opts: opts).toBridgeMap()
                
            } catch {
                return SiliconResult<Never>.failure(
                    code: .INTERNAL_ERROR,
                    message: error.localizedDescription,
                    nativeStack: nil
                ).toBridgeMap()
            }
        }
        
        // ---- Random Generator ----
        
        AsyncFunction("generateSecureRandomBytes") { (length: Int, format: RandomBytesFormat) -> [String: Any] in
            return siliconRandomGen.generate(length: length, format: format).toBridgeMap()
        }

        // ---- JOSE ----
        
        AsyncFunction("getJwk") { (alias: String, digest: KeyDigests?) -> [String: Any] in
            return siliconJose.getJwk(alias: alias, digest: digest).toBridgeMap()
        }
    }
}
