import Foundation
import Security
import LocalAuthentication
import DeviceCheck
import CryptoKit

enum SiliconKeystoreManager {
    
    static func generateKey(alias: String, opts: GenerateKeyOptions) -> SiliconResult<Void> {
        // Fail-fast if attest challenge is provided but attest is not supported
        if opts.attestChallenge != nil {
            if (opts.ios.hardwarePolicy != .REQUIRE_SECURE_ENCLAVE) {
                return .failure(code: .INVALID_ARGUMENT, message: "Hardware attestation cannot be performed on a software key. Set the hardware policy to \(HardwarePolicy.REQUIRE_SECURE_ENCLAVE) to enable it.", nativeStack: nil)
            }
            
            guard DCAppAttestService.shared.isSupported else {
                return .failure(code: .ATTEST_NOT_AVAILABLE, message: "Hardware attestation is unavailable on this device", nativeStack: nil)
            }
        }
        
        let tag = alias.data(using: .utf8)!
        
        // Alias Collision Check
        let existenceQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true
        ]
        
        let status = SecItemCopyMatching(existenceQuery as CFDictionary, nil)
        if status == errSecSuccess {
            return .failure(code: .ALIAS_IN_USE, message: "A key with alias '\(alias)' already exists", nativeStack: nil)
        }
        
        // Hardware Policy
        var hardwareRequested = false
        var useHardware = false
        switch opts.ios.hardwarePolicy {
        case .REQUIRE_SECURE_ENCLAVE:
            if !SecureEnclaveSupport.isAvailable() {
                return .failure(code: .HARDWARE_NOT_AVAILABLE, message: "Secure Enclave is required but unavailable", nativeStack: nil)
            }
            hardwareRequested = true
            useHardware = true
            
        case .PREFER_SECURE_ENCLAVE:
            hardwareRequested = true
            useHardware = SecureEnclaveSupport.isAvailable()
            
        case .SOFTWARE_ONLY:
            useHardware = false
        }
        
        // TODO: If requested key is symmetric, we use CryptoKit
        // TODO: If the purpose is ATTEST, we only create an ATTEST key and not a SecKey
        
        if hardwareRequested {
            // Purpose Validation Check
            // Secure Enclave hardware strictly disallows WRAP
            if opts.purposes.contains(.WRAP) {
                return .failure(
                    code: .INVALID_ARGUMENT,
                    message: "Secure Enclave does not support WRAP operations. To use it, change your hardware policy to \(HardwarePolicy.SOFTWARE_ONLY.rawValue).",
                    nativeStack: nil
                )
            }
            
            // ALL Secure Enclave keys must be EC_P256
            if opts.ios.algorithm != KeyAlgorithm.EC_P256 {
                return .failure(
                    code: .UNSUPPORTED,
                    message: "Secure Enclave does not support algorithm \(opts.ios.algorithm). Change the algorithm to \(KeyAlgorithm.EC_P256.rawValue) for hardware-backed cryptography, or change your hardware policy to \(HardwarePolicy.SOFTWARE_ONLY.rawValue).",
                    nativeStack: nil
                )
            }
        }
        
        // SIGN/VERIFY specific
        if opts.purposes.contains(.SIGN) || opts.purposes.contains(.VERIFY) {
            // if the signature padding alg was not provided, and the key is RSA, Set to the default (PSS)
            if opts.ios.signaturePaddingAlgorithm == nil {
                switch opts.ios.algorithm {
                case .RSA_2048, .RSA_3072, .RSA_4096:
                    opts.ios.signaturePaddingAlgorithm = .PSS
                
                default:
                    // Do nothing
                    break
                }
            }
            
            // If digests were not provided, determine the default based on the algorithm
            if opts.ios.digests == nil || opts.ios.digests?.count ?? 0 < 1{
                switch opts.ios.algorithm {
                case .EC_P256, .RSA_2048:
                    opts.ios.digests = [.SHA256]
                case .EC_P384, .RSA_3072:
                    opts.ios.digests = [.SHA384]
                case .EC_P521, .RSA_4096:
                    opts.ios.digests = [.SHA512]
                }
            }
            
            guard let allowedDigests = opts.ios.digests else {
                return .failure(
                    code: .GENERATE_KEY_FAILED,
                    message: "opts.ios.digests was nil after default value was set.",
                    nativeStack: nil
                )
            }
            
            var isEC = false
            
            switch opts.ios.algorithm {
            case .EC_P256:
                if !allowedDigests.contains(KeyDigests.SHA256) {
                    return .failure(
                        code: .INVALID_ARGUMENT,
                        message: "EC keys cannot be used for signing with any digest other than the one that matches the size of the key. Use \(KeyDigests.SHA256.rawValue) for \(KeyAlgorithm.EC_P256.rawValue) keys",
                        nativeStack: nil
                    )
                }
                isEC = true
            case .EC_P384:
                if !allowedDigests.contains(KeyDigests.SHA384) {
                    return .failure(
                        code: .INVALID_ARGUMENT,
                        message: "EC keys cannot be used for signing with any digest other than the one that matches the size of the key. Use \(KeyDigests.SHA384.rawValue) for \(KeyAlgorithm.EC_P384.rawValue) keys",
                        nativeStack: nil
                    )
                }
                isEC = true
            case .EC_P521:
                if !allowedDigests.contains(KeyDigests.SHA512) {
                    return .failure(
                        code: .INVALID_ARGUMENT,
                        message: "EC keys cannot be used for signing with any digest other than the one that matches the size of the key. Use \(KeyDigests.SHA512.rawValue) for \(KeyAlgorithm.EC_P521.rawValue) keys",
                        nativeStack: nil
                    )
                }
                isEC = true
            default:
                break
            }
            
            if isEC && allowedDigests.count > 1 {
                return .failure(
                    code: .INVALID_ARGUMENT,
                    message: "EC keys cannot be used for signing with multiple digests. Use the digest that matches the key size.",
                    nativeStack: nil
                )
            }
        }

        // Domain state will be nil if user auth is not required
        var domainState: Data? = nil
        
        if opts.userAuth.require {
            let context = LAContext()
            var deviceAuthError: NSError?
                
            // Check if the device has ANY form of secure lock screen
            if !context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &deviceAuthError) {
                if let error = deviceAuthError {
                    let laError = LAError(_nsError: error)
                    
                    if laError.code == .passcodeNotSet {
                        return SiliconResult.failure(
                            code: .DEVICE_NOT_SECURE,
                            message: "Cannot create an authenticated key. The device is not protected by a pin/password/pattern.",
                            nativeStack: nil
                        )
                    }
                }
            }
            
            var biometricsAuthError: NSError?
            if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &biometricsAuthError) {
                // This is a Data object containing the current biometric hash
                guard let currentDomainState = context.evaluatedPolicyDomainState else {
                    return .failure(code: .GENERATE_KEY_FAILED, message: "Domain state was nil.", nativeStack: nil)
                }
                domainState = currentDomainState
            }
            
            if let error = biometricsAuthError {
                let laError = LAError(_nsError: error)
                switch laError.code {
                case .biometryNotAvailable:
                    if opts.userAuth.policy == .BIOMETRICS_ONLY {
                        return .failure(code: .BIOMETRICS_NOT_AVAILABLE, message: "Biometrics are unavailable on this device.", nativeStack: nil)
                    }
                case .biometryNotEnrolled:
                    if opts.userAuth.policy == .BIOMETRICS_ONLY {
                        return .failure(code: .BIOMETRICS_NOT_ENROLLED, message: "User has not enrolled biometrics on this device.", nativeStack: nil)
                    }
                default:
                    return .failure(code: .GENERATE_KEY_FAILED, message: "Failed to evaluate policy 'deviceOwnerAuthenticationWithBiometrics': LAError code \(laError.code.rawValue)", nativeStack: nil)
                }
            }
            
            if domainState == nil && opts.userAuth.policy == .BIOMETRICS_ONLY {
                return .failure(
                    code: .GENERATE_KEY_FAILED,
                    message: "Domain state was nil when key had policy \(AuthPolicy.BIOMETRICS_ONLY.rawValue).",
                    nativeStack: nil
                )
            }
        }
        
        // Store metadata
        do {
            try KeyMetadataStore.store(alias: alias, opts: opts, isHardwareBacked: useHardware, domainState: domainState)
        } catch {
            return SiliconResult.failure(code: .GENERATE_KEY_FAILED, message: "Failed to save metadata to keychain", nativeStack: nil)
        }
        
        var result: SiliconResult<Void>
        if useHardware {
            result = GenerateKey.generateHardwareKey(
                alias: alias,
                tag: tag,
                opts: opts,
                isDomainStateStored: domainState != nil
            )
        } else {
            result = GenerateKey.generateSoftwareKey(
                alias: alias,
                tag: tag,
                opts: opts,
                isDomainStateStored: domainState != nil
            )
        }
        
        switch result {
        case .failure:
            // Cleanup metadata
            do {
                _ = try KeyMetadataStore.delete(alias: alias)
            } catch {
                // Ignore errors from the cleanup
            }
            return result
            
        case .success:
            return result
        }
    }
    
    static func deleteKey(alias: String) -> SiliconResult<Bool> {
        // TODO: Possibly implement this so that we cannot delete keys outside of our library
        /*
        do {
            let metadataExists = try KeychainHelper.exists(key: "\(alias)_metadata")
            
            if !metadataExists {
                return .failure(
                    code: .OPERATION_NOT_PERMITTED,
                    message: "Failed to delete key (\(alias)). Keys that are not generated with react-native-silicon cannot be deleted.",
                    nativeStack: nil
                )
            }
        }
        */
        
        let tag = alias.data(using: .utf8)! // TODO: Handle this (remove the !)
        
        // Delete the Standard SecKey
        let secKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag
        ]
        let secKeyStatus = SecItemDelete(secKeyQuery as CFDictionary)
        
        // If it's a system error (not just missing), fail-fast
        guard secKeyStatus == errSecSuccess || secKeyStatus == errSecItemNotFound else {
            return .failure(
                code: .DELETE_FAILED,
                message: "Failed to delete key (\(alias)). OSStatus: \(secKeyStatus)",
                nativeStack: nil
            )
        }
        
        var keyDeleted = (secKeyStatus == errSecSuccess)
        var wasError = false
        var errorMessages: [String] = [];
        
        // Wipe the attest ID (If one exists)
        var attestIdDeleted = false
        do {
            attestIdDeleted = try KeychainHelper.delete(key: "\(alias)_attest_id")
        } catch let error as KeychainHelper.KeychainHelperError {
            wasError = true
            errorMessages.append("Failed to delete attest ID: \(error.errorDescription)")
        } catch {
            wasError = true
            errorMessages.append("Failed to delete attest ID: \(error.localizedDescription)")
        }
        
        // Wipe the challenge (If one exists)
        var challengeDeleted = false
        do {
            challengeDeleted = try KeychainHelper.delete(key: "\(alias)_challenge")
        } catch let error as KeychainHelper.KeychainHelperError {
            wasError = true
            errorMessages.append("Failed to delete attest challenge: \(error.errorDescription)")
        } catch {
            wasError = true
            errorMessages.append("Failed to delete attest challenge: \(error.localizedDescription)")
        }
        
        // Wipe metadata
        var metadataDeleted = false
        do {
            metadataDeleted = try KeyMetadataStore.delete(alias: alias)
        } catch let error as KeyMetaDataDeleteError {
            wasError = true
            errorMessages.append("Failed to delete key metadata: \(error.errorDescription)")
        } catch {
            wasError = true
            errorMessages.append("Failed to delete key metadata: \(error.localizedDescription)")
        }
        
        
        if wasError {
            let finalErrMessage = "Key (\(alias)) was deleted but failed to fully clear keychain. Errors: " + errorMessages.joined(separator: ", ")
            return .failure(
                code: .DELETE_FAILED,
                message: finalErrMessage,
                nativeStack: nil
            )
        }
        
        // If anything was deleted, return true
        if keyDeleted || attestIdDeleted || challengeDeleted || metadataDeleted {
            return .success(true)
        } else {
            return .success(false)
        }
    }
    
    static func deleteAllKeys(prefix: String? = nil) -> SiliconResult<Int> {
        var deletedCount = 0
        var uniqueAliases = Set<String>()
        
        // --- Fetch all SecKey Aliases ---
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var keyResult: AnyObject?
        let keyStatus = SecItemCopyMatching(keyQuery as CFDictionary, &keyResult)
        
        if keyStatus == errSecSuccess, let items = keyResult as? [[String: Any]] {
            for item in items {
                // Standard SecKeys use kSecAttrApplicationTag as their alias
                if let tagData = item[kSecAttrApplicationTag as String] as? Data,
                   let alias = String(data: tagData, encoding: .utf8) {
                    uniqueAliases.insert(alias)
                }
            }
        } else if keyStatus != errSecItemNotFound {
            return .failure(code: .DELETE_ALL_FAILED, message: "Failed to read keys. OSStatus: \(keyStatus)", nativeStack: nil)
        }
        
        // List internal keychain data to find possible orphans
        do {
            let internalItems = try KeychainHelper.listAll()
            
            // If any items were found, add them to the uniqueAliases Set
            if let items = internalItems {
                for item in items {
                    if item.hasSuffix("_attest_id") {
                        let baseAlias = String(item.dropLast(10))
                        uniqueAliases.insert(baseAlias)
                    } else if item.hasSuffix("_challenge") {
                        let baseAlias = String(item.dropLast(10))
                        uniqueAliases.insert(baseAlias)
                    } else if item.hasSuffix("_metadata") {
                        let baseAlias = String(item.dropLast(9))
                        uniqueAliases.insert(baseAlias)
                    }
                }
            }
            
        } catch {
            // Ignore - We don't block the delete for non-essential cleanup
        }
        
        /*
        let passQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var passResult: AnyObject?
        let passStatus = SecItemCopyMatching(passQuery as CFDictionary, &passResult)
        
        if passStatus == errSecSuccess, let passItems = passResult as? [[String: Any]] {
            for item in passItems {
                // Generic Passwords use kSecAttrAccount as their alias
                if let accountStr = item[kSecAttrAccount as String] as? String {
                    if accountStr.hasSuffix("_attest_id") {
                        let baseAlias = String(accountStr.dropLast(10))
                        uniqueAliases.insert(baseAlias)
                    } else if accountStr.hasSuffix("_challenge") {
                        let baseAlias = String(accountStr.dropLast(10))
                        uniqueAliases.insert(baseAlias)
                    }
                }
            }
        } else if passStatus != errSecItemNotFound {
            return .failure(code: .DELETE_ALL_FAILED, message: "Failed to read attestation tokens. OSStatus: \(passStatus)", nativeStack: nil)
        }
         */
        
        var errorMessages: [String] = []
        
        // --- Filter and Execute Deletion ---
        for alias in uniqueAliases {
            // Apply the prefix filter if one was provided
            if let p = prefix, !alias.hasPrefix(p) {
                continue
            }
            
            // Funnel through deletion function
            let result = deleteKey(alias: alias)
            
            switch result {
            case .success(let deleted):
                deletedCount += 1
            case .failure(let code, let message, let nativeStack):
                errorMessages.append(message)
            }
        }
        
        // If any keys were not fully deleted, it is a failure
        if errorMessages.count > 0 {
            let baseMessage = "Failed to delete \(errorMessages.count) out of \(uniqueAliases.count) keys:\n  - "
            let combinedMessage = baseMessage + errorMessages.joined(separator: "\n  - ")
            return .failure(code: .DELETE_ALL_FAILED, message: combinedMessage, nativeStack: nil)
        }
        
        return .success(deletedCount)
    }
    
    static func keyExists(alias: String) -> SiliconResult<Bool> {
        let tag = alias.data(using: .utf8)! // TODO: Handle this (remove the !)
        
        // We only query the primary SecKey. If it's there, the key is usable.
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
        ]
        
        // Pass nil for the result because we don't actually need to load the key into memory,
        // we just want the OSStatus code.
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        
        if status == errSecSuccess {
            // The key was found
            return .success(true)
        } else if status == errSecItemNotFound {
            // The key was definitively not found
            return .success(false)
        } else {
            // Something went wrong at the OS level (e.g., Keychain locked, memory error)
            return .failure(
                code: .KEY_EXISTS_FAILED,
                message: "Failed to verify key existence for alias: \(alias). OSStatus code: \(status)",
                nativeStack: nil
            )
        }
    }
    
    static func listKeys(prefix: String?) -> SiliconResult<Any> {
        // Build the Keychain search query
        let query: [String: Any] = [
            // Query keys
            kSecClass as String: kSecClassKey,
            
            // Prevent duplicate aliases by only querying the Private key
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            
            // Get ALL keys, not just the first one
            kSecMatchLimit as String: kSecMatchLimitAll,
            
            // We only want the metadata (aliases).
            // Returning the raw key data here would be a massive performance hit.
            kSecReturnAttributes as String: true,
            kSecReturnData as String: false,
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        // Handle the "Empty Keystore" scenario
        // iOS treats "no items found" as an error status
        if status == errSecItemNotFound {
            return .success(([]))
        }
        
        // Handle actual OS/Keychain errors
        guard status == errSecSuccess else {
            return .failure(
                code: .LIST_KEYS_FAILED,
                message: "Failed to list keys from Keychain. OSStatus: \(status)",
                nativeStack: nil
            )
        }
        
        // Cast the raw C-array into a Swift dictionary array
        guard let items = result as? [[String: Any]] else {
            return .failure(
                code: .LIST_KEYS_FAILED,
                message: "Unexpected result format returned from Keychain",
                nativeStack: nil
            )
        }
        
        // Extract the aliases
        var aliases: [String] = []
        for item in items {
            var foundAlias: String? = nil
                    
            // Try our primary alias location first (Data)
            if let tagData = item[kSecAttrApplicationTag as String] as? Data {
                foundAlias = String(data: tagData, encoding: .utf8)
            }
            // Fallback for keys generated by other 3rd-party libraries (String)
            else if let labelString = item[kSecAttrLabel as String] as? String {
                foundAlias = labelString
            }
            
            if let validAlias = foundAlias {
                aliases.append(validAlias)
            }
        }
        
        // Apply the prefix filter
        let filteredAliases = prefix != nil ? aliases.filter { $0.hasPrefix(prefix!) } : aliases
        
        return .success(filteredAliases)
    }
    
    // NOTE: This should only ever return either String or Data
    static func getPubKey(alias: String, format: PubKeyFormat) -> SiliconResult<Any> {
        do {
            let pubkey = try getPubKeyData(alias: alias)
            
            let x509PubKeyResult = try pubKeyToX509(
                format: format,
                rawPublicKeyData: pubkey.rawData,
                // Read the key size and type from the Keychain attributes dictionary
                rawKeyType: pubkey.dict[kSecAttrKeyType as String],
                keySize: pubkey.dict[kSecAttrKeySizeInBits as String] as? Int
            )
            
            switch x509PubKeyResult {
            case .data(let rawSpki):
                return .success(rawSpki)
            case .str(let formattedPubKey):
                return .success(formattedPubKey)
            }

        } catch let error as GetPubKeyDataError {
            var code: SiliconErrorCode
            switch error {
            case .invalidAlias:
                code = .INVALID_ARGUMENT
            case .keyNotFound:
                code = .KEY_NOT_FOUND
            case .unsupportedKeyFamily:
                code = .UNSUPPORTED
            default:
                code = .GET_PUB_KEY_FAILED
            }
            return .failure(code: code, message: error.localizedDescription, nativeStack: nil)

        } catch let error as PubKeyFormatError {
            var code: SiliconErrorCode
            switch error {
            case .unsupportedECCurve, .unsupportedRSASize, .unsupportedKeyType:
                code = .UNSUPPORTED
            case .unknownKeySize, .unknownKeyType:
                code = .GET_PUB_KEY_FAILED
            }
            return .failure(code: code, message: error.localizedDescription, nativeStack: nil)
            
        } catch {
            return .failure(
                code: .GET_PUB_KEY_FAILED,
                message: error.localizedDescription,
                nativeStack: Thread.callStackSymbols.joined(separator: "\n")
            )
        }
    }
    
    static func validateKey(alias: String) -> SiliconResult<String> {
        guard let tag = alias.data(using: .utf8) else {
            return .failure(
                code: .INVALID_ARGUMENT,
                message: "Failed to encode alias to data. The alias must be valid UTF8.",
                nativeStack: nil
            )
        }
        
        // By strictly forbidding the UI, we force the Secure Enclave to evaluate
        // the key's internal state without throwing a Face ID prompt on the screen.
        let context = LAContext()
        context.interactionNotAllowed = true
        
        // Query the Keychain
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey, // Adjust to kSecClassGenericPassword if we store symmetric keys differently
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        // Map Apple's C-Engine OSStatus codes to SiliconResult
        switch status {
        case errSecSuccess:
            // Key exists, is perfectly healthy, and doesn't even require biometrics to read.
            return .success("VALID")
            
        case errSecInteractionNotAllowed:
            // Key exists and is 100% cryptographically healthy.
            // Apple throws this specific error because the key strictly requires biometrics
            // to be accessed, but we explicitly set interactionNotAllowed = true.
            return .success("VALID")
            
        case errSecItemNotFound:
            // The key doesn't exist in the Keychain.
            return .success("MISSING")
            
        case errSecAuthFailed, errSecDecode:
            // The key exists, but because the user enrolled new biometrics, it has been invalidated
            return .success("INVALIDATED")
            
        default:
            // A low-level system error, OS corruption, or unexpected OSStatus code.
            return .failure(
                code: .VALIDATE_KEY_FAILED,
                message: "Unrecognized OSStatus: \(status)",
                nativeStack: nil
            )
        }
    }
    
    func attestKey(alias: String, format: AttestFormat, pubKeyFormat: PubKeyFormat) async -> SiliconResult<[String: Any]> {
        // TODO: Implement guards to check that key is 1. in the secure enclave, and 2. able to be attested (a challenge was provided when it was generated)
        
        let pubKey: (rawData: Data, dict: [String : Any])
        do {
            pubKey = try getPubKeyData(alias: alias)

        } catch let error as GetPubKeyDataError {
            var code: SiliconErrorCode
            switch error {
            case .invalidAlias:
                code = .INVALID_ARGUMENT
            case .keyNotFound:
                code = .KEY_NOT_FOUND
            case .unsupportedKeyFamily:
                code = .UNSUPPORTED
            default:
                code = .ATTEST_KEY_FAILED
            }
            return .failure(code: code, message: error.localizedDescription, nativeStack: nil)
            
        } catch {
            return .failure(code: .ATTEST_KEY_FAILED, message: error.localizedDescription, nativeStack: nil)
            
        }
        
        // Retrieve the stored Challenge
        var challengeData: Data
        do {
            guard let challenge = try KeychainHelper.readData(key: "\(alias)_challenge") else {
                return .failure(code: .OPERATION_NOT_PERMITTED, message: "No attestation challenge was provided during key generation.", nativeStack: nil)
            }
            challengeData = challenge
        } catch let error as KeychainHelper.KeychainHelperError {
            return .failure(code: .ATTEST_KEY_FAILED, message: "Failed to read attest challenge from keychain: \(error.errorDescription)", nativeStack: nil)
        } catch {
            return .failure(code: .ATTEST_KEY_FAILED, message: "Failed to read attest challenge from keychain: \(error.localizedDescription)", nativeStack: nil)
        }

        
        // Retrieve the linked App Attest keyId
        var attestKeyId: String
        do {
            guard let id = try KeychainHelper.readStr(key: "\(alias)_attest_id") else {
                return .failure(code: .OPERATION_NOT_PERMITTED, message: "No App Attest key linked to this alias.", nativeStack: nil)
            }
            attestKeyId = id
        } catch let error as KeychainHelper.KeychainHelperError {
            return .failure(code: .ATTEST_KEY_FAILED, message: "Failed to read attest id from keychain: \(error.errorDescription)", nativeStack: nil)
        } catch {
            return .failure(code: .ATTEST_KEY_FAILED, message: "Failed to read attest id from keychain: \(error.localizedDescription)", nativeStack: nil)
        }
        
        // BINDING: Hash the Stored Challenge + SecKey Public Key
        var combinedData = challengeData
        combinedData.append(pubKey.rawData)
        
        let clientDataHash = Data(SHA256.hash(data: combinedData))
        
        // Request the Apple Certificate
        var cborData: Data
        do {
            cborData = try await attestService.attestKey(attestKeyId, clientDataHash: clientDataHash)
        } catch {
            return .failure(code: .ATTEST_KEY_FAILED, message: error.localizedDescription, nativeStack: nil)
        }
        
        do {
            // Format the pubkey
            let formattedPubKey = try pubKeyToX509(
                format: pubKeyFormat,
                rawPublicKeyData: pubKey.rawData,
                rawKeyType: pubKey.dict[kSecAttrKeyType as String],
                keySize: pubKey.dict[kSecAttrKeySizeInBits as String] as? Int
            )
            
            switch formattedPubKey {
            case .data(let pubKeyData):
                switch format {
                case .BYTES:
                return .success([
                    "platform": "IOS",
                    "signingPubKey": pubKeyData,
                        "attestationStatement": cborData
                    ])
                case .STRING:
                    return .success([
                        "platform": "IOS",
                        "signingPubKey": pubKeyData,
                        "attestationStatement": cborData.base64EncodedString()
                    ])
                }
                
            case .str(let pubKeyStr):
                switch format {
                case .BYTES:
                return .success([
                    "platform": "IOS",
                    "signingPubKey": pubKeyStr,
                        "attestationStatement": cborData
                    ])
                case .STRING:
                    return .success([
                        "platform": "IOS",
                        "signingPubKey": pubKeyStr,
                        "attestationStatement": cborData.base64EncodedString()
                ])
                }
            }
            
        } catch {
            return .failure(code: .ATTEST_KEY_FAILED, message: error.localizedDescription, nativeStack: nil)
        }
    }
    
    static func getKeyInfo(alias: String) -> SiliconResult<[String: Any?]> {
        // TODO: Check the metadata on the keychain, if it exists we can use the data from there
        
        guard let tag = alias.data(using: .utf8) else {
            return .failure(
                code: .INVALID_ARGUMENT,
                message: "Failed to encode alias to data",
                nativeStack: Thread.callStackSymbols.joined(separator: "\n")
            )
        }
        
        // Query the Keychain for the private key
        let privateQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var privateItem: CFTypeRef?
        let privateStatus = SecItemCopyMatching(privateQuery as CFDictionary, &privateItem)
        
        if privateStatus == errSecItemNotFound {
            return .failure(
                code: .KEY_NOT_FOUND,
                message: "No key exists for alias: '\(alias)'",
                nativeStack: nil
            )
        }
        
        guard privateStatus == errSecSuccess, let privateDict = privateItem as? [String: Any] else {
            return .failure(
                code: .GET_KEY_INFO_FAILED,
                message: "Failed to read Keychain item attributes. OSStatus: \(privateStatus)",
                nativeStack: Thread.callStackSymbols.joined(separator: "\n")
            )
        }
        
        // Query the Keychain for the public key
        let publicQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic, // Explicitly target Public Key
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var publicItem: CFTypeRef?
        let publicStatus = SecItemCopyMatching(publicQuery as CFDictionary, &publicItem)
        let publicDict = (publicStatus == errSecSuccess) ? (publicItem as? [String: Any]) : nil
        
        // Hardware Isolation Security Level
        // If the TokenID is SecureEnclave, it's hardware-backed. Otherwise, it's software Keychain.
        let tokenID = privateDict[kSecAttrTokenID as String] as? String
        let securityLevel = (tokenID == (kSecAttrTokenIDSecureEnclave as String)) ? "SECURE_ENCLAVE" : "SOFTWARE"
        
        var purposes: [String] = []
        // NOTE: Removed the block below - it is replaced by KeyMetadata
        /*
        // Extract Purposes
        
        // Check Private Key purposes
        if privateDict[kSecAttrCanSign as String] as? Bool == true { purposes.append("SIGN") }
        if privateDict[kSecAttrCanDecrypt as String] as? Bool == true { purposes.append("DECRYPT") }
        if privateDict[kSecAttrCanDerive as String] as? Bool == true { purposes.append("AGREE") }
        if privateDict[kSecAttrCanUnwrap as String] as? Bool == true { purposes.append("UNWRAP") }

        // Check Public Key purposes (if it exists)
        if let pubDict = publicDict {
            if pubDict[kSecAttrCanVerify as String] as? Bool == true { purposes.append("VERIFY") }
            if pubDict[kSecAttrCanEncrypt as String] as? Bool == true { purposes.append("ENCRYPT") }
            if pubDict[kSecAttrCanWrap as String] as? Bool == true { purposes.append("WRAP") }
        }
        */
        
        // Algorithm & Curve Extraction
        let rawKeyType = privateDict[kSecAttrKeyType as String]
        let keyType: String
        if let typeNum = rawKeyType as? NSNumber { keyType = typeNum.stringValue }
        else if let typeStr = rawKeyType as? String { keyType = typeStr }
        else { keyType = "UNKNOWN" }
        
        let keySize = privateDict[kSecAttrKeySizeInBits as String] as? Int
        var algorithm = "UNKNOWN"
        var curve: String? = nil
        
        if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) || keyType == (kSecAttrKeyTypeEC as String) {
            algorithm = "EC"
            if keySize == 256 { curve = "P-256" }
            else if keySize == 384 { curve = "P-384" }
            else if keySize == 521 { curve = "P-521" }
        } else if keyType == (kSecAttrKeyTypeRSA as String) {
            algorithm = "RSA"
        }/* else if keyType == (kSecAttrKeyTypeSymmetric as String) { // TODO: Implement this
            algorithm = "SYMMETRIC"
        }*/
        
        // Appraise the Access Control
        var isUserAuthRequired = false
        let accessibleClass = privateDict[kSecAttrAccessible as String] as? String
        
        // If an Access Control object exists, it almost certainly involves biometrics or passcode
        if privateDict[kSecAttrAccessControl as String] != nil {
            isUserAuthRequired = true
        }
        
        var infoMap: [String: Any?] = [
            "alias": alias,
            "algorithm": algorithm,
            "keySize": keySize,
            "securityLevel": securityLevel,
            "purposes": purposes,
            "isUserAuthRequired": isUserAuthRequired,
            "accessibleClass": accessibleClass
        ]
        
        if let safeCurve = curve {
            infoMap["curve"] = safeCurve
        }
        
        do {
            let metadata = try KeyMetadataStore.get(alias: alias)
            
            infoMap["userAuthValidityDurationSecs"] = metadata.userAuthTimeout
            infoMap["policy"] = metadata.userAuthPolicy
            
            purposes = []
            for purpose in metadata.purposes {
                purposes.append(purpose.rawValue)
            }
            infoMap["purposes"] = purposes
            
        } catch {
            return .failure(
                code: .GET_KEY_INFO_FAILED,
                message: "Failed to read key metadata",
                nativeStack: Thread.callStackSymbols.joined(separator: "\n")
            )
        }
        
        return .success(infoMap)
    }
}

// Internal hardware capability check utility
enum SecureEnclaveSupport {
    static func isAvailable() -> Bool {
        #if targetEnvironment(simulator)
        return false // Simulators never contain structural secure hardware environments
        #else
        // Evaluate real device capability flags
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage,
            nil
        )
        return accessControl != nil
        #endif
    }
}


