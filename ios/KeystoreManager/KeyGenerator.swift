import DeviceCheck

protocol KeyGenerating {
    func generateHardwareKey(alias: String, tag: Data, opts: GenerateKeyOptions, isDomainStateStored: Bool) async -> SiliconResult<Void>
    func generateSoftwareKey(alias: String, tag: Data, opts: GenerateKeyOptions, isDomainStateStored: Bool) -> SiliconResult<Void>
}

struct KeyGenerator: KeyGenerating {
    // MARK: - Dependencies
    let attestService: AttestServiceProvider
    let secItems: SecItemsProvider
    let secKeys: SecKeysProvider
    let secAccessControls: SecAccessControlsProvider
    let keychainHelper: KeychainHelping
    
    // MARK: - Init
    init(attestService: AttestServiceProvider,
         secItems: SecItemsProvider,
         secKeys: SecKeysProvider,
         secAccessControls: SecAccessControlsProvider,
         keychainHelper: KeychainHelping
    ){
        self.attestService = attestService
        self.secItems = secItems
        self.secKeys = secKeys
        self.secAccessControls = secAccessControls
        self.keychainHelper = keychainHelper
    }
    
    // MARK: - Hardware Keys
    func generateHardwareKey(alias: String, tag: Data, opts: GenerateKeyOptions, isDomainStateStored: Bool) async -> SiliconResult<Void> {
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
        
        // -- User Authentication --
        
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        
        if opts.userAuth.require {
            switch opts.userAuth.policy {
            case .BIOMETRICS_ONLY:
                if opts.userAuth.invalidateOnEnrollment {
                    if !isDomainStateStored {
                        return .failure(
                            code: .INTERNAL_ERROR,
                            message: "Domain state not stored when generating key with invalidateOnEnrollment",
                            nativeStack: nil
                        )
                    }
                    // Invalidate when new biometrics are added
                    flags.insert(.biometryCurrentSet)
                } else {
                    // Do not invalidate when new biometrics are added
                    flags.insert(.biometryAny)
                }
            case .BIOMETRICS_OR_CREDENTIAL:
                // Allow device Passcode fallback
                if opts.userAuth.invalidateOnEnrollment {
                    if isDomainStateStored {
                        // Invalidate when new biometrics are added
                        flags.insert(.biometryCurrentSet)
                        flags.insert(.devicePasscode)
                        flags.insert(.or)
                    } else {
                        flags.insert(.devicePasscode)
                    }
                    
                } else {
                    // Do not invalidate when new biometrics are added
                    flags.insert(.biometryAny)
                    flags.insert(.devicePasscode)
                    flags.insert(.or)
                }
            }
        }
        
        var error: Unmanaged<CFError>?
        guard let accessControl = secAccessControls.createWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, // Cannot leave this physical device via iCloud backups
            flags,
            &error
        ) else {
            let cfErr = error?.takeRetainedValue()
            return .failure(code: .GENERATE_KEY_FAILED, message: cfErr?.localizedDescription ?? "Unknown error", nativeStack: Thread.callStackSymbols.joined(separator: "\n"))
        }
        
        privateKeyAttrs[kSecAttrAccessControl as String] = accessControl
        
        // Secure Enclave is hardcoded to ["SIGN", "AGREE"]
        privateKeyAttrs[kSecAttrCanSign as String] = true
        privateKeyAttrs[kSecAttrCanDerive as String] = true
        
        attributes[kSecPrivateKeyAttrs as String] = privateKeyAttrs
        
        // Execute Key Generation
        var genError: Unmanaged<CFError>?
        guard let privateKey = secKeys.createRandomKey(attributes as CFDictionary, &genError) else {
            let err = genError?.takeRetainedValue()
            return .failure(code: .GENERATE_KEY_FAILED, message: err?.localizedDescription ?? "Unknown generation error", nativeStack: Thread.callStackSymbols.joined(separator: "\n"))
        }
        
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
                let secKeyStatus = secItems.delete(secKeyQuery as CFDictionary)
            }
            
            var keyId: String
            do {
                keyId = try await attestService.generateKey()
            } catch {
                cleanupSecKey();
                return .failure(code: .GENERATE_KEY_FAILED, message: error.localizedDescription, nativeStack: Thread.callStackSymbols.joined(separator: "\n"))
            }
            
            guard let challenge = opts.attestChallenge else {
                cleanupSecKey();
                return .failure(
                    code: .INTERNAL_ERROR,
                    message: "'opts.attestChallenge' was nil",
                    nativeStack: Thread.callStackSymbols.joined(separator: "\n")
                )
            }
            
            // Persist the alias -> keyId map locally so attestKey can find it
            do {
                try keychainHelper.saveStr(key: "\(alias)_attest_id", value: keyId)
            } catch let error as KeychainHelperError {
                cleanupSecKey()
                return .failure(
                    code: .GENERATE_KEY_FAILED,
                    message: "Failed to store key identifier in keychain: \(error.errorDescription)",
                    nativeStack: Thread.callStackSymbols.joined(separator: "\n")
                )
            } catch {
                cleanupSecKey()
                return .failure(
                    code: .GENERATE_KEY_FAILED,
                    message: "Failed to store key identifier in keychain: \(error.localizedDescription)",
                    nativeStack: Thread.callStackSymbols.joined(separator: "\n")
                )
            }
            
            // Persist the alias -> challenge map locally so attestKey can find it
            do {
                try keychainHelper.saveData(key: "\(alias)_challenge", data: challenge)
                
            } catch let error as KeychainHelperError {
                do { _ = try keychainHelper.delete(key: "\(alias)_attest_id") } catch {} // Ignore failed cleanup
                cleanupSecKey()
                
                return .failure(
                    code: .GENERATE_KEY_FAILED,
                    message: "Failed to store key identifier in keychain: \(error.errorDescription)",
                    nativeStack: Thread.callStackSymbols.joined(separator: "\n")
                )
                
            } catch {
                do { _ = try keychainHelper.delete(key: "\(alias)_attest_id") } catch {} // Ignore failed cleanup
                cleanupSecKey()
                
                return .failure(
                    code: .GENERATE_KEY_FAILED,
                    message: "Failed to store key identifier in keychain: \(error.localizedDescription)",
                    nativeStack: Thread.callStackSymbols.joined(separator: "\n")
                )
            }
        }
        
        return .success(())
    }
    
    // MARK: - Software Keys
    func generateSoftwareKey(alias: String, tag: Data, opts: GenerateKeyOptions, isDomainStateStored: Bool) -> SiliconResult<Void> {
        var keyType: String
        var keySize: Int
        
        switch opts.ios.algorithm {
        case .EC_P256:
            keyType = kSecAttrKeyTypeECSECPrimeRandom as String
            keySize = 256
        case .EC_P384:
            keyType = kSecAttrKeyTypeECSECPrimeRandom as String
            keySize = 384
        case .EC_P521:
            keyType = kSecAttrKeyTypeECSECPrimeRandom as String
            keySize = 521
        case .RSA_2048:
            keyType = kSecAttrKeyTypeRSA as String
            keySize = 2048
        case .RSA_3072:
            keyType = kSecAttrKeyTypeRSA as String
            keySize = 3072
        case .RSA_4096:
            keyType = kSecAttrKeyTypeRSA as String
            keySize = 4096
        }
        
        // Initialize Core Generation Parameters
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: keyType,
            kSecAttrKeySizeInBits as String: keySize
        ]
        
        var privateKeyAttrs: [String: Any] = [
            kSecAttrApplicationTag as String: tag,
            kSecAttrIsPermanent as String: true,
            
            // Block icloud backups for this key
            //kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            
            // Set label so we can determine hardware/software keys
            //kSecAttrLabel as String: "software" // NOTE: Removed due to error
        ]
        
        var publicKeyAttrs: [String: Any] = [:]
        
        // -- User Authentication --
        
        
        
        if opts.userAuth.require {
            var flags: SecAccessControlCreateFlags = []
            
            switch opts.userAuth.policy {
            case .BIOMETRICS_ONLY:
                if opts.userAuth.invalidateOnEnrollment {
                    if !isDomainStateStored {
                        return .failure(
                            code: .INTERNAL_ERROR,
                            message: "Domain state not stored when generating key with invalidateOnEnrollment",
                            nativeStack: nil
                        )
                    }
                    // Invalidate when new biometrics are added
                    flags.insert(.biometryCurrentSet)
                } else {
                    // Do not invalidate when new biometrics are added
                    flags.insert(.biometryAny)
                }
            case .BIOMETRICS_OR_CREDENTIAL:
                // Allow device Passcode fallback
                if opts.userAuth.invalidateOnEnrollment {
                    if isDomainStateStored {
                        // Invalidate when new biometrics are added
                        flags.insert(.biometryCurrentSet)
                        flags.insert(.devicePasscode)
                        flags.insert(.or)
                    } else {
                        flags.insert(.devicePasscode)
                    }
                    
                } else {
                    // Do not invalidate when new biometrics are added
                    flags.insert(.biometryAny)
                    flags.insert(.devicePasscode)
                    flags.insert(.or)
                }
            }
            
            var error: Unmanaged<CFError>?
            guard let accessControl = secAccessControls.createWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, // Cannot leave this physical device via iCloud backups
                flags,
                &error
            ) else {
                let cfErr = error?.takeRetainedValue()
                return .failure(
                    code: .GENERATE_KEY_FAILED,
                    message: cfErr?.localizedDescription ?? "Failed to create Access Control",
                    nativeStack: Thread.callStackSymbols.joined(separator: "\n")
                )
            }
            
            privateKeyAttrs[kSecAttrAccessControl as String] = accessControl
            
        } else {
            privateKeyAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
        
        // -- Purposes --
        
        // Default all purposes to false
        privateKeyAttrs[kSecAttrCanSign as String] = false
        privateKeyAttrs[kSecAttrCanVerify as String] = false
        publicKeyAttrs[kSecAttrCanSign as String] = false
        publicKeyAttrs[kSecAttrCanVerify as String] = false
        
        privateKeyAttrs[kSecAttrCanEncrypt as String] = false
        privateKeyAttrs[kSecAttrCanDecrypt as String] = false
        publicKeyAttrs[kSecAttrCanEncrypt as String] = false
        publicKeyAttrs[kSecAttrCanDecrypt as String] = false
        
        privateKeyAttrs[kSecAttrCanDerive as String] = false
        publicKeyAttrs[kSecAttrCanDerive as String] = false
        
        privateKeyAttrs[kSecAttrCanUnwrap as String] = false
        privateKeyAttrs[kSecAttrCanWrap as String] = false
        publicKeyAttrs[kSecAttrCanUnwrap as String] = false
        publicKeyAttrs[kSecAttrCanWrap as String] = false
        
        
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
                publicKeyAttrs[kSecAttrCanDerive as String] = true
            case KeyPurpose.WRAP:
                return .failure(code: .UNSUPPORTED, message: "The WRAP purpose is not yet implemented for iOS", nativeStack: nil)
                // publicKeyAttrs[kSecAttrCanWrap as String] = true
            }
        }
        
        attributes[kSecPrivateKeyAttrs as String] = privateKeyAttrs
        attributes[kSecPublicKeyAttrs as String] = publicKeyAttrs
        
        // Execute Key Generation
        var genError: Unmanaged<CFError>?
        guard let privateKey = secKeys.createRandomKey(attributes as CFDictionary, &genError) else {
            let err = genError?.takeRetainedValue()
            return .failure(
                code: .GENERATE_KEY_FAILED,
                message: err?.localizedDescription ?? "Unknown generation error",
                nativeStack: Thread.callStackSymbols.joined(separator: "\n")
            )
        }

        return .success(())
    }
    
    // MARK: - Helpers
    /*
    private func formatPubkey(privateKey: SecKey, opts: GenerateKeyOptions) -> SiliconResult<String?> {
        // Extract the attributes from the SecKey
        guard let attributes = SecKeyCopyAttributes(privateKey) as? [String: Any] else {
            return .failure(code: .GENERATE_KEY_FAILED, message: "Failed to copy attributes from the generated SecKey.", nativeStack: nil)
        }
        
        // Extract the Public Key object from the SecKey
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            return .failure(code: .GENERATE_KEY_FAILED, message: "Failed to extract public key from generated pair.", nativeStack: nil)
        }
        
        // Extract the raw bytes
        var exportError: Unmanaged<CFError>?
        guard let rawPublicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
            let err = exportError?.takeRetainedValue()
            return .failure(code: .GENERATE_KEY_FAILED, message: err?.localizedDescription ?? "Failed to export public key bytes.", nativeStack: nil)
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
                code: .GENERATE_KEY_FAILED,
                message: error.localizedDescription,
                nativeStack: Thread.callStackSymbols.joined(separator: "\n")
            )
        }
    }
     */
}
