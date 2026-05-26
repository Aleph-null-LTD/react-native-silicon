import Foundation
import Security
import LocalAuthentication
import DeviceCheck

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
            return try GenerateKey.generateSoftwareKey()
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
    
    /*
    static func attestKey(alias: String) -> SiliconResult<[String: Any]> {
        
        // Retrieve the SecKey Public Key bytes
        guard let secKeyBytes = getSecKeyPublicBytes(alias: alias) else {
            return .failure(code: "KEY_NOT_FOUND", message: "Signing key not found.", nativeStack: nil)
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
        combinedData.append(secKeyBytes)
        
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
        
        return .success([
            "platform": "IOS",
            "signingPubKey": secKeyBytes.base64EncodedString(),
            "attestationStatement": validBlob
        ])
    }
    */
    
    // ---- OLD ATTEST FUNCTIONS -----
    /*
    static func attestKey(alias: String, challenge: String) -> SiliconResult<String> {
        // 1. Fetch the hardware keyId reference we saved during step 1
        guard let keyId = KeychainHelper.read(key: alias) else {
            return .failure(code: "KEY_NOT_FOUND", message: "No attested key container found for alias '\(alias)'.", nativeStack: nil)
        }
        
        let service = DCAppAttestService.shared
        let semaphore = DispatchGroup()
        var nativeError: Error?
        var attestationBlob: String?
        
        // 2. iOS requires the server challenge to be securely hashed via SHA-256
        let challengeData = challenge.data(using: .utf8)!
        let clientDataHash = Data(SHA256.hash(data: challengeData))
        
        semaphore.enter()
        // 3. Attest the key itself against Apple's certificate authority
        service.attestKey(keyId, clientDataHash: clientDataHash) { attestationObject, error in
            if let error = error {
                nativeError = error
            } else if let attestationObject = attestationObject {
                // This binary object IS the complete WebAuthn/Apple X.509 certificate chain
                attestationBlob = attestationObject.base64EncodedString()
            }
            semaphore.leave()
        }
        _ = semaphore.wait(timeout: .distantFuture)
        
        if let error = nativeError {
            return .failure(code: "ATTESTATION_FAILED", message: error.localizedDescription, nativeStack: nil)
        }
        
        guard let base64CertChain = attestationBlob else {
            return .failure(code: "UNKNOWN_ERROR", message: "Failed to extract certificate chain bytes.", nativeStack: nil)
        }
        
        // Return the raw certificate chain back to the JS layer!
        return .success(base64CertChain)
    }
    
    static func attestKey(alias: String, challenge: String) -> SiliconResult<[String: Any]> {
            // 1. Retrieve the standard SecKey Public Key bytes
            guard let secKeyBytes = getSecKeyPublicBytes(alias: alias) else {
                return .failure(code: "KEY_NOT_FOUND", message: "Signing key not found.", nativeStack: nil)
            }
            
            // 2. Retrieve the linked App Attest keyId
            guard let attestKeyId = KeychainHelper.read(key: "\(alias)_attest_id") else {
                return .failure(code: "ATTEST_ID_NOT_FOUND", message: "No App Attest key linked to this alias.", nativeStack: nil)
            }
            
            // 3. THE MAGIC BINDING: Hash the Server Challenge + The SecKey Public Key
            let challengeData = challenge.data(using: .utf8)!
            var combinedData = challengeData
            combinedData.append(secKeyBytes)
            
            let clientDataHash = Data(SHA256.hash(data: combinedData))
            
            // 4. Request the Apple Certificate
            let semaphore = DispatchGroup()
            var attestationBlob: String?
            
            semaphore.enter()
            DCAppAttestService.shared.attestKey(attestKeyId, clientDataHash: clientDataHash) { attStmt, error in
                attestationBlob = attStmt?.base64EncodedString()
                semaphore.leave()
            }
            _ = semaphore.wait(timeout: .distantFuture)
            
            guard let validBlob = attestationBlob else {
                return .failure(code: "ATTESTATION_FAILED", message: "Failed to get certificate from Apple.", nativeStack: nil)
            }
            
            // Return exactly what the JS layer needs to route to the backend
            return .success([
                "platform": "ios",
                "signingPublicKey": secKeyBytes.base64EncodedString(),
                "attestationStatement": validBlob
            ])
        }
     */
    
    /*
    static func getPubKey(alias: String) -> String {
        //Extract Raw Public Bits and Format Uniformly
        guard let rawPublicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return .failure(code: "PUBLIC_KEY_EXTRACTION_FAILED", message: "Could not copy bits out of memory container", nativeStack: nil)
        }
        
        // CRITICAL CROSS-PLATFORM ALIGNMENT:
        // iOS extracts raw EC points (65 bytes). Android outputs full X.509 SubjectPublicKeyInfo (SPKI) structures.
        // We prepend the standard ASN.1 SPKI header bytes for an uncompressed P-256 key so we output identical keys.
        let asn1Header = Data([
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
        ])
        var uniformPublicKeyBytes = asn1Header
        uniformPublicKeyBytes.append(rawPublicKeyData)
        
        // Output String Serialization matching PubkeyFormat
        let outputString: String
        switch opts.pubkeyFormat {
        case .PEM:
            let base64Encoded = uniformPublicKeyBytes.base64EncodedString(options: .lineLength64Characters)
            outputString = "-----BEGIN PUBLIC KEY-----\n\(base64Encoded)\n-----END PUBLIC KEY-----"
        case .B64:
            outputString = uniformPublicKeyBytes.base64EncodedString()
        }
        
        return .success(outputString)
    }
     */
    
    // TODO: When deleting a key, if the key has an attestChallenge, we need to delete from the keychain too
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


