import Foundation
import Security
import LocalAuthentication
import DeviceCheck
import CryptoKit

enum SiliconKeystoreManager {
    
    static func generateKey(alias: String, opts: GenerateKeyOptions) throws -> SiliconResult<String?> {
        // Fail-fast if attest challenge is provided but attest is not supported
        if opts.attestChallenge != nil {
            guard DCAppAttestService.shared.isSupported else {
                return .failure(code: "ATTEST_NOT_SUPPORTED", message: "Hardware attestation is unavailable on this device", nativeStack: nil)
            }
            
            if (opts.ios.hardwarePolicy != .REQUIRE_SECURE_ENCLAVE) {
                return .failure(code: "INVALID_OPTIONS", message: "Hardware attestation cannot be performed on a software key. Set the hardware policy to \(HardwarePolicy.REQUIRE_SECURE_ENCLAVE) to enable it.", nativeStack: nil)
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
            return .failure(code: "ALIAS_IN_USE", message: "A key with alias '\(alias)' already exists", nativeStack: nil)
        }
        
        // Hardware Policy
        var hardwareRequested = false
        var useHardware = false
        switch opts.ios.hardwarePolicy {
        case .REQUIRE_SECURE_ENCLAVE:
            if !SecureEnclaveSupport.isAvailable() {
                return .failure(code: "HARDWARE_NOT_AVAILABLE", message: "Secure Enclave is required but unavailable", nativeStack: nil)
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
                    code: "UNSUPPORTED_PURPOSE",
                    message: "iOS: Secure Enclave does not support WRAP operations. To use it, change your hardware policy to \(HardwarePolicy.SOFTWARE_ONLY.rawValue).",
                    nativeStack: nil
                )
            }
            
            // ALL Secure Enclave keys must be EC_P256
            if opts.ios.algorithm != KeyAlgorithm.EC_P256 {
                return .failure(
                    code: "UNSUPPORTED_KEY_FAMILY",
                    message: "iOS: Secure Enclave does not support algorithm \(opts.ios.algorithm). Change the algorithm to \(KeyAlgorithm.EC_P256.rawValue) for hardware-backed cryptography, or change your hardware policy to \(HardwarePolicy.SOFTWARE_ONLY.rawValue).",
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
                throw SiliconException(
                    code: "INVALID_DIGESTS",
                    message: "Silicon Error: iOS: opts.ios.digests was nil after default value was set"
                )
            }
            
            var isEC = false
            
            switch opts.ios.algorithm {
            case .EC_P256:
                if !allowedDigests.contains(KeyDigests.SHA256) {
                    return .failure(
                        code: "INVALID_PARAMETER",
                        message: "iOS: EC keys cannot be used for signing with any digest other than the one that matches the size of the key. Use \(KeyDigests.SHA256.rawValue) for \(KeyAlgorithm.EC_P256.rawValue) keys",
                        nativeStack: nil
                    )
                }
                isEC = true
            case .EC_P384:
                if !allowedDigests.contains(KeyDigests.SHA384) {
                    return .failure(
                        code: "INVALID_PARAMETER",
                        message: "iOS: EC keys cannot be used for signing with any digest other than the one that matches the size of the key. Use \(KeyDigests.SHA384.rawValue) for \(KeyAlgorithm.EC_P384.rawValue) keys",
                        nativeStack: nil
                    )
                }
                isEC = true
            case .EC_P521:
                if !allowedDigests.contains(KeyDigests.SHA512) {
                    return .failure(
                        code: "INVALID_PARAMETER",
                        message: "iOS: EC keys cannot be used for signing with any digest other than the one that matches the size of the key. Use \(KeyDigests.SHA512.rawValue) for \(KeyAlgorithm.EC_P521.rawValue) keys",
                        nativeStack: nil
                    )
                }
                isEC = true
            default:
                break
            }
            
            if isEC && allowedDigests.count > 1 {
                return .failure(
                    code: "INVALID_PARAMETER",
                    message: "iOS: EC keys cannot be used for signing with multiple digests. Use the digest that matches the key size.",
                    nativeStack: nil
                )
            }
        }

        // Store metadata
        do {
            try KeyMetadataStore.store(alias: alias, opts: opts, isHardwareBacked: useHardware)
        } catch {
            return SiliconResult.failure(code: "GENERATE_KEY_FAILED", message: "iOS: Failed to save metadata to keychain", nativeStack: nil)
        }
        
        do {
            var ret: SiliconResult<String?>
            if useHardware {
                ret = try GenerateKey.generateHardwareKey(alias: alias, tag: tag, opts: opts)
            } else {
                ret = try GenerateKey.generateSoftwareKey(alias: alias, tag: tag, opts: opts)
            }
            
            switch ret {
            case .failure:
                // Cleanup metadata
                _ = KeyMetadataStore.delete(alias: alias)
                return ret
            case .success:
                return ret
            }
            
        } catch {
            // Cleanup metadata
            _ = KeyMetadataStore.delete(alias: alias)
            
            // Re-throw
            throw error
        }
    }
    
    static func deleteKey(alias: String) -> SiliconResult<Bool> {
        let tag = alias.data(using: .utf8)!
            
        // Delete the Standard SecKey
        let secKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag
        ]
        let secKeyStatus = SecItemDelete(secKeyQuery as CFDictionary)
        
        // Safely handle the optional App Attest Token
        let attestKeyStatus: OSStatus = errSecSuccess
        
        // Check if it exists before trying to delete, or just check its deletion status
        // Safely handle the optional App Attest Token AND the Challenge
        var attestKeyClean = true

        if KeychainHelper.readStr(key: "\(alias)_attest_id") != nil {
            // Wipe the ID
            let statusId = KeychainHelper.delete(key: "\(alias)_attest_id")
            
            // Wipe the stored challenge
            let statusChallenge = KeychainHelper.delete(key: "\(alias)_challenge")
            
            attestKeyClean = statusId && statusChallenge
        }
        
        let metadataClean = KeyMetadataStore.delete(alias: alias)
        
        let primaryKeyClean = (secKeyStatus == errSecSuccess || secKeyStatus == errSecItemNotFound)
        
        if primaryKeyClean && attestKeyClean {
            return .success(true)
        } else {
            return .failure(
                code: "DELETE_FAILED",
                message: "Failed to fully clear keychain. Primary Key Status: \(secKeyStatus), Attest Token Status: \(attestKeyStatus), Metadata Status: \(metadataClean)",
                nativeStack: nil
            )
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
            return .failure(code: "BULK_DELETE_FAILED", message: "Failed to read primary keys. OSStatus: \(keyStatus)", nativeStack: nil)
        }
        
        // --- Fetch all Attestation / Challenge Orphans ---
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
            return .failure(code: "BULK_DELETE_FAILED", message: "Failed to read attestation tokens. OSStatus: \(passStatus)", nativeStack: nil)
        }
        
        // --- Filter and Execute Deletion ---
        for alias in uniqueAliases {
            // Apply the prefix filter if one was provided
            if let p = prefix, !alias.hasPrefix(p) {
                continue
            }
            
            // Funnel through deletion function
            let result = deleteKey(alias: alias)
            
            if case .success = result {
                deletedCount += 1
            }
        }
        
        return .success(deletedCount)
    }
    
    static func keyExists(alias: String) -> SiliconResult<Bool> {
        let tag = alias.data(using: .utf8)!
        
        // We only query the primary SecKey. If it's there, the key is usable.
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag
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
                code: "KEY_EXISTS_FAILED",
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
                code: "KEY_LIST_FAILED",
                message: "Failed to list keys from Keychain. OSStatus: \(status)",
                nativeStack: nil
            )
        }
        
        // Cast the raw C-array into a Swift dictionary array
        guard let items = result as? [[String: Any]] else {
            return .failure(
                code: "KEY_LIST_FAILED",
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
    
    static func getPubKey(alias: String, format: PubKeyFormat) -> SiliconResult<String> {
        do {
            let pubkey = try getPubKeyData(alias: alias)
            
            let formattedPubKey = try pubKeyToX509(
                format: format,
                rawPublicKeyData: pubkey.rawData,
                // Read the key size and type from the Keychain attributes dictionary
                rawKeyType: pubkey.dict[kSecAttrKeyType as String],
                keySize: pubkey.dict[kSecAttrKeySizeInBits as String] as? Int
            )
            return .success(formattedPubKey)

        } catch let error as GetPubKeyDataError {
            var code: String
            switch error {
            case .invalidAlias:
                code = "INVALID_ALIAS"
            case .keyNotFound:
                code = "KEY_NOT_FOUND"
            case .unsupportedKeyFamily:
                code = "UNSUPPORTED_KEY_FAMILY"
            default:
                code = "GET_PUB_KEY_FAILED"
            }
            return .failure(code: code, message: error.localizedDescription, nativeStack: nil)

        } catch {
            return .failure(
                code: "GET_PUB_KEY_FAILED",
                message: error.localizedDescription,
                nativeStack: Thread.callStackSymbols.joined(separator: "\n")
            )
        }
    }
    
    static func validateKey(alias: String) -> SiliconResult<String> {
        guard let tag = alias.data(using: .utf8) else {
            return .failure(
                code: "KEY_VALIDATION_FAILED",
                message: "Invalid alias format",
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
                code: "KEY_VALIDATION_FAILED",
                message: "Unrecognized OSStatus: \(status)",
                nativeStack: nil
            )
        }
    }
    
    static func attestKey(alias: String, pubKeyFormat: PubKeyFormat) -> SiliconResult<[String: Any]> {
        // TODO: Implement guards to check that key is 1. in the secure enclave, and 2. able to be attested (a challenge was provided when it was generated)
        
        let pubKey: (rawData: Data, dict: [String : Any])
        do {
            pubKey = try getPubKeyData(alias: alias)

        } catch let error as GetPubKeyDataError {
            var code: String
            switch error {
            case .invalidAlias:
                code = "INVALID_ALIAS"
            case .keyNotFound:
                code = "KEY_NOT_FOUND"
            case .unsupportedKeyFamily:
                code = "UNSUPPORTED_KEY_FAMILY"
            default:
                code = "ATTESTATION_FAILED"
            }
            return .failure(code: code, message: error.localizedDescription, nativeStack: nil)
            
        } catch {
            return .failure(code: "ATTESTATION_FAILED", message: error.localizedDescription, nativeStack: nil)
            
        }
        
        // Retrieve the linked App Attest keyId
        guard let attestKeyId = KeychainHelper.readStr(key: "\(alias)_attest_id") else {
            return .failure(code: "ATTEST_ID_NOT_FOUND", message: "No App Attest key linked to this alias.", nativeStack: nil)
        }
        
        // Retrieve the stored Challenge
        guard let storedChallenge = KeychainHelper.readStr(key: "\(alias)_challenge") else {
            return .failure(code: "CHALLENGE_NOT_FOUND", message: "No attestation challenge was provided during key generation.", nativeStack: nil)
        }
        
        // BINDING: Hash the Stored Challenge + SecKey Public Key
        let challengeData = storedChallenge.data(using: .utf8)!
        var combinedData = challengeData
        combinedData.append(pubKey.rawData)
        
        let clientDataHash = Data(SHA256.hash(data: combinedData))
        
        // Request the Apple Certificate
        let semaphore = DispatchGroup()
        var attestationBlob: String?
        var nativeError: Error?
        
        semaphore.enter()
        DCAppAttestService.shared.attestKey(attestKeyId, clientDataHash: clientDataHash) { attStmt, error in
            nativeError = error
            attestationBlob = attStmt?.base64EncodedString()
            semaphore.leave()
        }
        _ = semaphore.wait(timeout: .distantFuture)
        
        if let error = nativeError {
            return .failure(code: "ATTESTATION_FAILED", message: error.localizedDescription, nativeStack: nil)
        }
        
        guard let validBlob = attestationBlob else {
            return .failure(code: "ATTESTATION_FAILED", message: "Failed to compile Apple certificate.", nativeStack: nil)
        }
        
        var formattedPubKey: String
        
        // Format the pubkey
        do {
            formattedPubKey = try pubKeyToX509(
                format: pubKeyFormat,
                rawPublicKeyData: pubKey.rawData,
                rawKeyType: pubKey.dict[kSecAttrKeyType as String],
                keySize: pubKey.dict[kSecAttrKeySizeInBits as String] as? Int
            )
            
            return .success([
                "platform": "IOS",
                "signingPubKey": formattedPubKey, // TODO: allow multiple encodings (PEM, B64, B64URL)
                "attestationStatement": validBlob
            ])
        } catch {
            return .failure(code: "ATTESTATION_FAILED", message: error.localizedDescription, nativeStack: nil)
        }
    }
    
    static func getKeyInfo(alias: String) -> SiliconResult<[String: Any?]> {
        // TODO: Check the metadata on the keychain, if it exists we can use the data from there
        
        guard let tag = alias.data(using: .utf8) else {
            return .failure(
                code: "INVALID_ALIAS",
                message: "Failed to encode alias to data",
                nativeStack: Thread.callStackSymbols.joined(separator: "\n")
            )
        }
        
        // Query the Keychain for the Key and its Attributes
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecItemNotFound {
            return .failure(
                code: "KEY_NOT_FOUND",
                message: "No key exists for alias: '\(alias)'",
                nativeStack: nil
            )
        }
        
        guard status == errSecSuccess, let dict = item as? [String: Any] else {
            return .failure(
                code: "GET_KEY_INFO_FAILED",
                message: "Failed to read Keychain item attributes. OSStatus: \(status)",
                nativeStack: Thread.callStackSymbols.joined(separator: "\n")
            )
        }
        
        // Hardware Isolation Security Level
        // If the TokenID is SecureEnclave, it's hardware-backed. Otherwise, it's software Keychain.
        let tokenID = dict[kSecAttrTokenID as String] as? String
        let securityLevel = (tokenID == (kSecAttrTokenIDSecureEnclave as String)) ? "SECURE_ENCLAVE" : "SOFTWARE"
        
        // Extract Purposes
        var purposes: [String] = []
        if dict[kSecAttrCanSign as String] as? Bool == true { purposes.append("SIGN") }
        if dict[kSecAttrCanVerify as String] as? Bool == true { purposes.append("VERIFY") }
        if dict[kSecAttrCanEncrypt as String] as? Bool == true { purposes.append("ENCRYPT") }
        if dict[kSecAttrCanDecrypt as String] as? Bool == true { purposes.append("DECRYPT") }
        if dict[kSecAttrCanDerive as String] as? Bool == true { purposes.append("AGREE") }
        if dict[kSecAttrCanWrap as String] as? Bool == true { purposes.append("WRAP") }
        if dict[kSecAttrCanUnwrap as String] as? Bool == true { purposes.append("UNWRAP") }
        
        // Algorithm & Curve Extraction
        let rawKeyType = dict[kSecAttrKeyType as String]
        let keyType: String
        if let typeNum = rawKeyType as? NSNumber { keyType = typeNum.stringValue }
        else if let typeStr = rawKeyType as? String { keyType = typeStr }
        else { keyType = "UNKNOWN" }
        
        let keySize = dict[kSecAttrKeySizeInBits as String] as? Int
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
        let accessibleClass = dict[kSecAttrAccessible as String] as? String
        
        // If an Access Control object exists, it almost certainly involves biometrics or passcode
        if dict[kSecAttrAccessControl as String] != nil {
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
            
        } catch {
            return .failure(
                code: "GET_KEY_INFO_FAILED",
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


