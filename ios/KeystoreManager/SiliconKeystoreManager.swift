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
                    message: "The Apple Secure Enclave does not support direct ENCRYPT, DECRYPT, or WRAP operations. It only supports SIGN, VERIFY, and AGREE. To use them, change your hardware policy to \"SOFTWARE_ONLY\".",
                    nativeStack: nil
                )
            }
            
            // ALL hardware backed keys must be ES256
            // if key algorithm is not ES256 - return failure
            if opts.ios.algorithm != KeyAlgorithm.ES256 {
                return .failure(
                    code: "UNSUPPORTED_KEY_FAMILY",
                    message: "The Apple Secure Enclave does not support algorithm \"\(opts.ios.algorithm)\". Change the algorithm to \"ES256\" for hardware-backed cryptography.",
                    nativeStack: nil
                )
            }
        }
        
        if useHardware {
            return try GenerateKey.generateHardwareKey(alias: alias, tag: tag, opts: opts)
        } else {
            return try GenerateKey.generateSoftwareKey(alias: alias, tag: tag, opts: opts)
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
        var attestKeyStatus: OSStatus = errSecSuccess
        
        // Check if it exists before trying to delete, or just check its deletion status
        // Safely handle the optional App Attest Token AND the Challenge
        let attestKeyAlias = "\(alias)_attest_id"
        let challengeAlias = "\(alias)_challenge"

        var attestKeyClean = true

        if KeychainHelper.read(key: attestKeyAlias) != nil {
            // Wipe the ID
            let attestQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: attestKeyAlias
            ]
            let statusId = SecItemDelete(attestQuery as CFDictionary)
            
            // Wipe the stored challenge
            let challengeQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: challengeAlias
            ]
            let statusChallenge = SecItemDelete(challengeQuery as CFDictionary)
            
            attestKeyClean = (statusId == errSecSuccess || statusId == errSecItemNotFound) &&
                             (statusChallenge == errSecSuccess || statusChallenge == errSecItemNotFound)
        }
        
        let primaryKeyClean = (secKeyStatus == errSecSuccess || secKeyStatus == errSecItemNotFound)
        
        if primaryKeyClean && attestKeyClean {
            return .success(true)
        } else {
            return .failure(
                code: "DELETE_FAILED",
                message: "Failed to fully clear keychain. Primary Key Status: \(secKeyStatus), Attest Token Status: \(attestKeyStatus)",
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
            
            // Funnel through our comprehensive deletion function
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
    
    static func validateKey(alias: String) throws -> SiliconResult<String> {
        throw SiliconException(
            code: "NOT_IMPLEMENTED",
            message: "validateKey not implemented"
        )
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
        guard let attestKeyId = KeychainHelper.read(key: "\(alias)_attest_id") else {
            return .failure(code: "ATTEST_ID_NOT_FOUND", message: "No App Attest key linked to this alias.", nativeStack: nil)
        }
        
        // Retrieve the stored Challenge
        guard let storedChallenge = KeychainHelper.read(key: "\(alias)_challenge") else {
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


