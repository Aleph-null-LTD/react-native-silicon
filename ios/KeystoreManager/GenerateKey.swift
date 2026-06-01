import DeviceCheck

// TODO: Anywhere where a failure is returned after the key has been generated, we need to cleanup and delete the key and any related attest stuff in the Keychain

enum GenerateKey {
    static func generateHardwareKey(alias: String, tag: Data, opts: GenerateKeyOptions) throws -> SiliconResult<String?> {
        // Initialize Core Generation Parameters
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, // Matches NIST P-256 / secp256r1
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        ]
        
        var privateKeyAttrs: [String: Any] = [
            kSecAttrApplicationTag as String: tag,
            kSecAttrIsPermanent as String: true,
            
            // Block icloud backups for this key
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            
            // Set label so we can determine hardware/software keys
            //kSecAttrLabel as String: "hardware" // NOTE: Removed due to error
        ]
        
        var publicKeyAttrs: [String: Any] = [:]
        
        // -- User Authentication --
        
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        
        if opts.userAuth.require {
            switch opts.userAuth.policy {
            case .BIOMETRICS_ONLY:
                if opts.userAuth.invalidateOnEnrollment {
                    // Invalidate when new biometrics are added
                    flags.insert(.biometryCurrentSet)
                } else {
                    // Do not invalidate when new biometrics are added
                    flags.insert(.biometryAny)
                }
            case .BIOMETRICS_OR_CREDENTIAL:
                // Allow device Passcode fallback
                if opts.userAuth.invalidateOnEnrollment {
                    // Invalidate when new biometrics are added
                    flags.insert(.biometryCurrentSet)
                    flags.insert(.devicePasscode)
                    flags.insert(.or)
                } else {
                    // Do not invalidate when new biometrics are added
                    flags.insert(.biometryAny)
                    flags.insert(.devicePasscode)
                    flags.insert(.or)
                }
            }
            
            // TODO: Implement auth timeouts here
        }
        
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, // Cannot leave this physical device via iCloud backups
            flags,
            &error
        ) else {
            let cfErr = error?.takeRetainedValue()
            return .failure(code: "KEY_GENERATION_FAILED", message: cfErr?.localizedDescription ?? "Unknown error", nativeStack: Thread.callStackSymbols.joined(separator: "\n"))
        }
        
        privateKeyAttrs[kSecAttrAccessControl as String] = accessControl
        
        // -- Purposes --
        
        // Default all purposes to false
        // TODO: When writing software backup, do these default to true or false?
        //privateKeyAttrs[kSecAttrCanSign as String] = false
        //publicKeyAttrs[kSecAttrCanVerify as String] = false
        
        //publicKeyAttrs[kSecAttrCanEncrypt as String] = false
        //privateKeyAttrs[kSecAttrCanDecrypt as String] = false
        
        //privateKeyAttrs[kSecAttrCanDerive as String] = false
        
        // Secure Enclave is hardcoded to ["SIGN", "AGREE"]
        privateKeyAttrs[kSecAttrCanSign as String] = true
        privateKeyAttrs[kSecAttrCanDerive as String] = true
        
        // Set the defined purposes to true
        for purpose in opts.purposes {
            switch purpose {
            case KeyPurpose.SIGN:
                privateKeyAttrs[kSecAttrCanSign as String] = true
                
            case KeyPurpose.VERIFY:
                publicKeyAttrs[kSecAttrCanVerify as String] = true
                
            case KeyPurpose.ENCRYPT:
                // TODO: ENCRYPT/DECRYPT needs to use ECIES
                publicKeyAttrs[kSecAttrCanEncrypt as String] = true
                
            case KeyPurpose.DECRYPT:
                privateKeyAttrs[kSecAttrCanDecrypt as String] = true
                
            case KeyPurpose.AGREE:
                privateKeyAttrs[kSecAttrCanDerive as String] = true
                
            case KeyPurpose.WRAP:
                // TODO: Implement WRAP (possibly using ECIES)
                throw SiliconException(code: "NOT_IMPLEMENTED", message: "The WRAP purpose is not yet implemented for iOS")
            }
        }
        
        attributes[kSecPrivateKeyAttrs as String] = privateKeyAttrs
        
        if !publicKeyAttrs.isEmpty {
            //attributes[kSecPublicKeyAttrs as String] = publicKeyAttrs
        }
        
        // Execute Key Generation
        var genError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &genError) else {
            let err = genError?.takeRetainedValue()
            return .failure(code: "KEY_GENERATION_FAILED", message: err?.localizedDescription ?? "Unknown generation error", nativeStack: Thread.callStackSymbols.joined(separator: "\n"))
        }
        
        // TODO: If SecKey generation succeeds, but attest key generation fails, we need to delete the SecKey to clean up and then return a failure
        
        // Create the attest key if a challenge was provided
        // on iOS we cannot use a single key for both SIGN/VERIFY and ATTEST, so we create a 2nd key for attestation and link them using the keychain
        // Note: This involves a network call to Apple's servers
        if opts.attestChallenge != nil {
            // Cleanup function that will be called if something goes wrong
            func cleanupSecKey() {
                // Delete the SecKey (cleanup)
                let secKeyQuery: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecAttrApplicationTag as String: tag
                ]
                let secKeyStatus = SecItemDelete(secKeyQuery as CFDictionary)
            }
            
            let semaphore = DispatchGroup()
            var nativeError: Error?
            var generatedKeyId: String?
            
            semaphore.enter()
            
            // Generate the hardware-trapped key pair
            DCAppAttestService.shared.generateKey { keyId, error in
                if let error = error {
                    nativeError = error
                } else {
                    generatedKeyId = keyId
                }
                semaphore.leave()
            }
            _ = semaphore.wait(timeout: .distantFuture)
            
            if let error = nativeError {
                cleanupSecKey();
                return .failure(code: "KEY_GENERATION_FAILED", message: error.localizedDescription, nativeStack: Thread.callStackSymbols.joined(separator: "\n"))
            }
            
            guard let keyId = generatedKeyId else {
                cleanupSecKey();
                return .failure(code: "KEY_GENERATION_FAILED", message: "Failed to retrieve hardware key identifier", nativeStack: Thread.callStackSymbols.joined(separator: "\n"))
            }
            
            guard let challenge = opts.attestChallenge else {
                cleanupSecKey();
                throw SiliconException(code: "NIL_CHALLENGE", message: "'opts.attestChallenge' was nil")
            }
            
            // Persist the alias -> keyId map locally so attestKey can find it
            KeychainHelper.save(key: "\(alias)_attest_id", value: keyId)
            
            // Persist the alias -> challenge map locally so attestKey can find it
            KeychainHelper.save(key: "\(alias)_challenge", value: challenge)
        }
        
        // TODO: for symmetric keys we will skip the pubkey formatting and return nil

        return formatPubkey(privateKey: privateKey, opts: opts)
    }
    
    static func generateSoftwareKey(alias: String, tag: Data, opts: GenerateKeyOptions) throws -> SiliconResult<String?> {
        // TODO: Implement this
        
        throw SiliconException(code: "NOT_IMPLEMENTED", message: "Software key fallback is not implemented")
        
        
    }
    
    private static func formatPubkey(privateKey: SecKey, opts: GenerateKeyOptions) -> SiliconResult<String?> {
        // Extract the attributes from the SecKey
        guard let attributes = SecKeyCopyAttributes(privateKey) as? [String: Any] else {
            return .failure(code: "COPY_ATTRIBUTES_FAILED", message: "Failed to copy attributes from the generated SecKey.", nativeStack: nil)
        }
        
        // Extract the Public Key object from the SecKey
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            return .failure(code: "PUBLIC_KEY_EXTRACTION_FAILED", message: "Failed to extract public key from generated pair.", nativeStack: nil)
        }
        
        // Extract the raw bytes
        var exportError: Unmanaged<CFError>?
        guard let rawPublicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
            let err = exportError?.takeRetainedValue()
            return .failure(code: "PUBLIC_KEY_EXPORT_FAILED", message: err?.localizedDescription ?? "Failed to export public key bytes.", nativeStack: nil)
        }
        
        do {
            let formattedPubKey = try pubKeyToX509(
                format: opts.pubkeyFormat,
                rawPublicKeyData: rawPublicKeyData,
                rawKeyType: attributes[kSecAttrKeyType as String],
                keySize: attributes[kSecAttrKeySizeInBits as String] as? Int
            )
            return .success(formattedPubKey)
            
        } catch {
            return .failure(
                code: "KEY_GENERATION_FAILED",
                message: error.localizedDescription,
                nativeStack: Thread.callStackSymbols.joined(separator: "\n")
            )
        }
    }
}
