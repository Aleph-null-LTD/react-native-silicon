import DeviceCheck

enum GenerateKey {
    static func generateHardwareKey(alias: String, tag: Data, opts: GenerateKeyOptions) throws -> SiliconResult<String?> {
        // Initialize Core Generation Parameters
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, // Matches NIST P-256 / secp256r1
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrApplicationTag as String: tag,
            kSecAttrIsPermanent as String: true,
            
            // Set description so we can determine hardware VS software keys
            kSecAttrDescription as String: "hardware"
        ]
        
        attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        
        var privateKeyAttrs: [String: Any] = [:]
        var publicKeyAttrs: [String: Any] = [:]
        
        // -- User Authentication --
        
        if opts.userAuth.require {
            var flags: SecAccessControlCreateFlags = []
            
            switch opts.userAuth.policy {
            case .BIOMETRICS_ONLY:
                if opts.userAuth.invalidateOnEnrollment {
                    flags.insert(.biometryCurrentSet) // Invalidates when new fingerprints/faces add
                } else {
                    flags.insert(.biometryAny)
                }
            case .BIOMETRICS_OR_CREDENTIAL:
                flags.insert(.userPresence) // Allows device Passcode fallback
            }
            
            flags.insert(.privateKeyUsage)
            
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
        }
        
        // -- Purposes --
        
        // Default all purposes to false
        privateKeyAttrs[kSecAttrCanSign as String] = false
        publicKeyAttrs[kSecAttrCanVerify as String] = false
        
        publicKeyAttrs[kSecAttrCanEncrypt as String] = false
        privateKeyAttrs[kSecAttrCanDecrypt as String] = false
        
        privateKeyAttrs[kSecAttrCanDerive as String] = false
        
        // Set the defined purposes to true
        for purpose in opts.purposes {
            switch purpose {
            case KeyPurpose.SIGN:
                privateKeyAttrs[kSecAttrCanSign as String] = true
                
            case KeyPurpose.VERIFY:
                publicKeyAttrs[kSecAttrCanVerify as String] = true
                
            case KeyPurpose.ENCRYPT:
                publicKeyAttrs[kSecAttrCanEncrypt as String] = true
                
            case KeyPurpose.DECRYPT:
                privateKeyAttrs[kSecAttrCanDecrypt as String] = true
                
            case KeyPurpose.AGREE:
                privateKeyAttrs[kSecAttrCanDerive as String] = true
                
            case KeyPurpose.WRAP:
                // TODO: Implement WRAP (possibly using ECIES)
                throw SiliconException(code: "NOT_IMPLEMENTED", message: "WRAP purpose is not yet implemented for iOS")
            }
        }
            
        attributes[kSecPrivateKeyAttrs as String] = privateKeyAttrs
        attributes[kSecPublicKeyAttrs as String] = publicKeyAttrs
        
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
            
            // Persist the alias -> keyId map locally so attestKey can find it
            KeychainHelper.save(key: "\(alias)_attest_id", value: keyId)
            
            if let challenge = opts.attestChallenge {
                // Persist the alias -> challenge map locally so attestKey can find it
                KeychainHelper.save(key: "\(alias)_challenge", value: challenge)
            } else {
                cleanupSecKey();
                throw SiliconException(code: "NIL_CHALLENGE", message: "'opts.attestChallenge' was nil")
            }
        }
        
        // TODO: for symmetric keys (always software based) we will skip the pubkey and return nil
        
        // Extract the Public Key object from the generated Private Key reference
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            return .failure(code: "PUBLIC_KEY_EXTRACTION_FAILED", message: "Failed to extract public key from generated pair.", nativeStack: nil)
        }
        
        // Extract the raw bytes
        var exportError: Unmanaged<CFError>?
        guard let rawPublicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
            let err = exportError?.takeRetainedValue()
            return .failure(code: "PUBLIC_KEY_EXPORT_FAILED", message: err?.localizedDescription ?? "Failed to export public key bytes.", nativeStack: nil)
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
        let formattedPubKey: String
        switch opts.pubkeyFormat {
        case .PEM:
            let base64Encoded = uniformPublicKeyBytes.base64EncodedString(options: .lineLength64Characters)
            formattedPubKey = "-----BEGIN PUBLIC KEY-----\n\(base64Encoded)\n-----END PUBLIC KEY-----"
            
        case .B64:
            formattedPubKey = uniformPublicKeyBytes.base64EncodedString()
        }
        
        return .success(formattedPubKey)
    }
    
    static func generateSoftwareKey() throws -> SiliconResult<String?> {
        // TODO: Implement this
        
        throw SiliconException(code: "NOT_IMPLEMENTED", message: "Software key fallback is not implemented")
    }
}
