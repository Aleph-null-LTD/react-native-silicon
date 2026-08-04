import Foundation
import Security

struct SiliconVerifier {
    // MARK: - Dependencies
    // Providers
    private var secItems: SecItemsProvider
    private var secKeys: SecKeysProvider
    
    // Internal
    private var keyMetadataStore: KeyMetadataStoring
    
    // MARK: init()
    init(secItems: SecItemsProvider, secKeys: SecKeysProvider, keyMetadataStore: KeyMetadataStoring) {
        self.secItems = secItems
        self.secKeys = secKeys
        self.keyMetadataStore = keyMetadataStore
    }
    
    // MARK: - verify()
    func verify(payload: PayloadType, signature: PayloadType, opts: VerifyOptions) -> SiliconResult<Bool> {
        let publicKey: SecKey
        var algorithm: VerifyAlgorithms
        
        // Resolve the Public Key
        if let alias = opts.alias, !alias.isEmpty { // Internal key was requested
            let internalKeyResult = extractInternalKey(alias: alias, opts: opts)
            
            switch internalKeyResult {
            case .success(let internalKey):
                publicKey = internalKey.publicKey
                algorithm = internalKey.algorithm
            case .failure(let code, let message, let nativeStack):
                return .failure(code: code, message: message, nativeStack: nativeStack)
            }
            
        } else if let pubk = opts.pubkey { // External key was supplied
            let externalKeyResult = extractExternalKey(pubkey: pubk, opts: opts)
            
            switch externalKeyResult {
            case .success(let externalKey):
                publicKey = externalKey.publicKey
                algorithm = externalKey.algorithm
            case .failure(let code, let message, let nativeStack):
                return .failure(code: code, message: message, nativeStack: nativeStack)
            }
            
        } else {
            return .failure(code: .INVALID_ARGUMENT, message: "Either 'alias' or 'pubkey' must be supplied.", nativeStack: nil)
        }
        
        let payloadData: Data
        switch payload {
        case .text(let str):
            guard let rawBytes = str.data(using: .utf8) else {
                return .failure(code: .MALFORMED_DATA, message: "Failed to convert payload to raw bytes.", nativeStack: nil)
            }
            payloadData = rawBytes
            
        case .byteArr(let rawBytes):
                payloadData = rawBytes
        }
        
        let signatureData: Data
        switch signature {
        case .text(let str):
            guard let rawBytes = Data(base64Encoded: str) else {
                return .failure(code: .MALFORMED_DATA, message: "Failed to decode signature from Base64.", nativeStack: nil)
            }
            signatureData = rawBytes
            
        case .byteArr(let rawBytes):
            signatureData = rawBytes
        }
        
        // Determine the SecKey algorithm
        var secKeyAlg: SecKeyAlgorithm
        var isEC = false
        
        switch algorithm {
        // Elliptic Curve DSA (ECDSA)
        case .ES256:
            secKeyAlg = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
            isEC = true
        case .ES384:
            secKeyAlg = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384
            isEC = true
        case .ES512:
            secKeyAlg = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512
            isEC = true
        
        // RSA PKCS#1 v1.5
        case .RS256: secKeyAlg = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
        case .RS384: secKeyAlg = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA384
        case .RS512: secKeyAlg = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA512
            
        // RSA PSS
        case .PS256: secKeyAlg = SecKeyAlgorithm.rsaSignatureMessagePSSSHA256
        case .PS384: secKeyAlg = SecKeyAlgorithm.rsaSignatureMessagePSSSHA384
        case .PS512: secKeyAlg = SecKeyAlgorithm.rsaSignatureMessagePSSSHA512
        }
        
        var finalSignature: Data
        
        // Ensure DER formatting for EC keys
        if isEC {
            let derResult = ensureDerSignature(signatureData: signatureData, algorithm: algorithm)
            
            switch derResult {
            case .failure(let code, let message, let nativeStack):
                return .failure(code: code, message: message, nativeStack: nativeStack)
            case .success(let derData):
                finalSignature = derData
            }
            
        } else {
            finalSignature = signatureData
        }
        
        // Hardware/OS Verification
        var verifyError: Unmanaged<CFError>?
        let isValid = secKeys.verifySignature(
            publicKey,
            secKeyAlg,
            payloadData as CFData,
            finalSignature as CFData,
            &verifyError
        )
        
        return .success(isValid)
    }
    
    // MARK: - extractInternalKey()
    private func extractInternalKey(alias: String, opts: VerifyOptions) -> SiliconResult<(algorithm: VerifyAlgorithms, publicKey: SecKey)> {
        var algorithm: VerifyAlgorithms
        
        // Fetch from local Keychain
        guard let tag = alias.data(using: .utf8) else {
            return .failure(code: .INVALID_ARGUMENT, message: "Alias could not be converted to raw data.", nativeStack: nil)
        }
        
        // Get the key metadata
        /*
        guard let metadata = try? KeyMetadataStore.get(alias: alias) else {
            return .failure(code: .VERIFY_FAILED, message: "Failed to retrieve key metadata.", nativeStack: nil)
        }
        */
        
        var metadata: KeyMetadata
        let metadataResult = Result { try keyMetadataStore.get(alias: alias) }
        
        switch metadataResult {
        case .success(let md):
            metadata = md
        case .failure(let error):
            return .failure(code: .VERIFY_FAILED, message: "\(error.localizedDescription)", nativeStack: nil)
        }
        
        // Ensure the key has the VERIFY purpose
        if !metadata.purposes.contains(KeyPurpose.VERIFY) {
            return .failure(code: .KEY_POLICY_VIOLATION, message: "Key does not have the VERIFY purpose.", nativeStack: nil)
        }
        
        guard let allowedDigests = metadata.digests else {
            return .failure(code: .INTERNAL_ERROR, message: "Key metadata does not have a any allowed digests.", nativeStack: nil)
        }
        
        // Query keychain for the key
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnAttributes as String: true, // Gets Metadata dict for the key
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let status = secItems.copyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            return .failure(code: .KEY_NOT_FOUND, message: "No key with alias '\(alias)'.", nativeStack: nil)
        }
        
        guard let dict = item as? [String: Any] else {
            return .failure(code: .VERIFY_FAILED, message: "Failed to read public key attributes.", nativeStack: nil)
        }
        
        // Extract the SecKey ref
        guard let rawRef = dict[kSecValueRef as String] else {
            return .failure(code: .VERIFY_FAILED, message: "Could not locate SecKey reference in dictionary.", nativeStack: nil)
        }
        let keyRef = rawRef as! SecKey
        
        // Extract the public key from the SecKey reference
        guard let publicKey = secKeys.copyPublicKey(keyRef) else {
            return .failure(code: .VERIFY_FAILED, message: "Could not extract public key from Keychain.", nativeStack: nil)
        }
        
        // Get the key size in bits
        guard let keySize = dict[kSecAttrKeySizeInBits as String] as? Int else {
            return .failure(code: .VERIFY_FAILED, message: "Failed to read public key size.", nativeStack: nil)
        }
        
        // Get the key type and safely coerce it
        let rawKeyType = dict[kSecAttrKeyType as String]
        let keyType: String
        if let typeNum = rawKeyType as? NSNumber {
            // If it's a number, convert it to a string
            keyType = typeNum.stringValue
        } else if let typeStr = rawKeyType as? String {
            // If it's already a string, keep it
            keyType = typeStr
        } else {
            return .failure(code: .VERIFY_FAILED, message: "rawKeyType was an unexpected type: got \(String(describing: type(of: keyType))) expected String | Int", nativeStack: nil)
        }
        
        if let safeAlgorithm = opts.algorithm {
            // Algorithm was explicitly provided
            
            let digest: KeyDigests
            
            if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) || keyType == (kSecAttrKeyTypeEC as String) {
                // Ensure it is compatible with the key family
                switch safeAlgorithm {
                case .ES256:
                    if keySize != 256 {
                        return .failure(
                            code: .INCOMPATIBLE,
                            message: "key (\(alias)) is an EC key and must use the algorithm that matches it's size (\(VerifyAlgorithms.ES256.rawValue)).",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA256
                case .ES384:
                    if keySize != 384 {
                        return .failure(
                            code: .INCOMPATIBLE,
                            message: "key (\(alias)) is an EC key and must use the algorithm that matches it's size (\(VerifyAlgorithms.ES384.rawValue)).",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA384
                case .ES512:
                    if keySize != 512 {
                        return .failure(
                            code: .INCOMPATIBLE,
                            message: "key (\(alias)) is an EC key and must use the algorithm that matches it's size (\(VerifyAlgorithms.ES512.rawValue)).",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA512
                default:
                    return .failure(code: .INCOMPATIBLE, message: "Cannot use \(safeAlgorithm) with a non-EC key.", nativeStack: nil)
                }
                
            } else if keyType == (kSecAttrKeyTypeRSA as String) {
                guard let safeSigPaddingAlg = metadata.signaturePaddingAlgorithm else {
                    return .failure(
                        code: .INTERNAL_ERROR,
                        message: "Metadata did not contain signaturePaddingAlgorithm when attempting verify with RSA key.",
                        nativeStack: nil
                    )
                }
                
                switch safeAlgorithm {
                case .RS256:
                    if safeSigPaddingAlg != .PKCS1 {
                        return .failure(
                            code: .KEY_POLICY_VIOLATION,
                            message: "Cannot use \(VerifyAlgorithms.RS256.rawValue) with key (\(alias)). Please use \(VerifyAlgorithms.PS256.rawValue).",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA256
                case .RS384:
                    if safeSigPaddingAlg != .PKCS1 {
                        return .failure(
                            code: .KEY_POLICY_VIOLATION,
                            message: "Cannot use \(VerifyAlgorithms.RS384.rawValue) with key (\(alias)). Please use \(VerifyAlgorithms.PS384.rawValue).",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA384
                case .RS512:
                    if safeSigPaddingAlg != .PKCS1 {
                        return .failure(
                            code: .KEY_POLICY_VIOLATION,
                            message: "Cannot use \(VerifyAlgorithms.RS512.rawValue) with key (\(alias)). Please use \(VerifyAlgorithms.ES512.rawValue).",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA512
                case .PS256:
                    if safeSigPaddingAlg != .PSS {
                        return .failure(
                            code: .KEY_POLICY_VIOLATION,
                            message: "Cannot use \(VerifyAlgorithms.PS256.rawValue) with key (\(alias)). Please use \(VerifyAlgorithms.RS256.rawValue).",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA256
                case .PS384:
                    if safeSigPaddingAlg != .PSS {
                        return .failure(
                            code: .KEY_POLICY_VIOLATION,
                            message: "Cannot use \(VerifyAlgorithms.PS384.rawValue) with key (\(alias)). Please use \(VerifyAlgorithms.RS384.rawValue).",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA384
                case .PS512:
                    if safeSigPaddingAlg != .PSS {
                        return .failure(
                            code: .KEY_POLICY_VIOLATION,
                            message: "Cannot use \(VerifyAlgorithms.PS512.rawValue) with key (\(alias)). Please use \(VerifyAlgorithms.RS512.rawValue).",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA512
                default:
                    return .failure(code: .INCOMPATIBLE, message: "Cannot use \(safeAlgorithm.rawValue) with a non-RSA key.", nativeStack: nil)
                }
                
            } else {
                return .failure(
                    code: .INCOMPATIBLE,
                    message: "Key (\(alias)) is not an EC or RSA key and cannot be used for verify.",
                    nativeStack: nil
                )
            }
            
            // Ensure the digest is in the list of allowed digests
            if (!allowedDigests.contains(digest)) {
                return .failure(
                    code: .KEY_POLICY_VIOLATION,
                    message: "Key with alias \(alias) does not allow the \(digest) digest. Allowed digests: \(allowedDigests)",
                    nativeStack: nil
                )
            }
            
            algorithm = safeAlgorithm

        } else {
            // Algorithm was not provided, so determine the default algorithm based on the key size and family
            
            let attemptAlgorithm: VerifyAlgorithms
            let digest: KeyDigests
            
            if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) || keyType == (kSecAttrKeyTypeEC as String) {
                // Key is EC
                switch keySize {
                case 256:
                    attemptAlgorithm = .ES256
                    digest = .SHA256
                case 384:
                    attemptAlgorithm = .ES384
                    digest = .SHA384
                case 521:
                    attemptAlgorithm = .ES512
                    digest = .SHA512
                default:
                    return .failure(code: .UNSUPPORTED, message: "Verify does not support key size (\(keySize)).", nativeStack: nil)
                }
                
            } else if keyType == (kSecAttrKeyTypeRSA as String) {
                // Key is RSA
                guard let safeSigPaddingAlg = metadata.signaturePaddingAlgorithm else {
                    return .failure(
                        code: .INTERNAL_ERROR,
                        message: "Metadata did not contain signaturePaddingAlgorithm when attempting verify with RSA key.",
                        nativeStack: nil
                    )
                }
                
                switch keySize {
                case 2048, 2047:
                    switch safeSigPaddingAlg {
                    case .PKCS1:
                        attemptAlgorithm = .RS256
                    case .PSS:
                        attemptAlgorithm = .PS256
                    }
                    digest = .SHA256
                case 3072, 3071:
                    switch safeSigPaddingAlg {
                    case .PKCS1:
                        attemptAlgorithm = .RS384
                    case .PSS:
                        attemptAlgorithm = .PS384
                    }
                    digest = .SHA384
                case 4096, 4095:
                    switch safeSigPaddingAlg {
                    case .PKCS1:
                        attemptAlgorithm = .RS512
                    case .PSS:
                        attemptAlgorithm = .PS512
                    }
                    digest = .SHA512
                default:
                    return .failure(
                        code: .UNSUPPORTED,
                        message: "Verify does not support key size (\(keySize)).",
                        nativeStack: nil
                    )
                }
                
            } else {
                return .failure(code: .UNSUPPORTED, message: "Key family (\(keyType.utf8)) is not supported for verify.", nativeStack: nil)
            }
            
            // Check if the digest is in the list of allowed digests
            if (allowedDigests.contains(digest)) {
                algorithm = attemptAlgorithm
            } else {
                return .failure(
                    code: .INCOMPATIBLE,
                    message: "Could not use default verify algorithm for key (\(alias)). Please set the algorithm explicitly in the options.",
                    nativeStack: nil
                )
            }
        }
        
        return .success((algorithm: algorithm, publicKey: publicKey))
    }
    
    // MARK: - extractExternalKey()
    private func extractExternalKey(pubkey: PayloadType, opts: VerifyOptions) -> SiliconResult<(algorithm: VerifyAlgorithms, publicKey: SecKey)> {
        var algorithm: VerifyAlgorithms
        
        var keyData: Data
        switch (pubkey) {
        case .text(let base64Str):
            // Parse from External X.509 Base64
            guard let d = Data(base64Encoded: base64Str, options: .ignoreUnknownCharacters) else {
                return .failure(code: .MALFORMED_DATA, message: "Could not decode public key.", nativeStack: nil)
            }
            keyData = d
        case .byteArr(let bytes):
            keyData = bytes
        }
        
        guard let safeAlgorithm = opts.algorithm else {
            return .failure(
                code: .INVALID_ARGUMENT,
                message: "opts.algorithm is undefined",
                nativeStack: nil
            )
        }
        algorithm = safeAlgorithm
        
        var keyType: String
        var keySizeInBits: Int?
        
        switch algorithm {
        // Elliptic Curve DSA (ECDSA)
        case .ES256:
            keyType = kSecAttrKeyTypeECSECPrimeRandom as String
            keySizeInBits = 256
        case .ES384:
            keyType = kSecAttrKeyTypeECSECPrimeRandom as String
            keySizeInBits = 384
        case .ES512:
            keyType = kSecAttrKeyTypeECSECPrimeRandom as String
            keySizeInBits = 521
        
        // RSA PKCS#1 v1.5 and RSA PSS
        case .RS256, .RS384, .RS512, .PS256, .PS384, .PS512:
            keyType = kSecAttrKeyTypeRSA as String
            keySizeInBits = nil // iOS will determine the key size from the modulus of the X.509 byte array
            
        }
        
        // Apple requires explicit typing to parse X.509 SPKI data correctly
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: keyType,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
        ]
        
        if keySizeInBits != nil {
            attributes[kSecAttrKeySizeInBits as String] = keySizeInBits
        }
        
        // Create the SecKey
        var error: Unmanaged<CFError>?
        guard let publicKey = secKeys.createWithData(keyData as CFData, attributes as CFDictionary, &error) else {
            let errStr = error?.takeRetainedValue().localizedDescription ?? "Unknown parse error"
            return .failure(code: .MALFORMED_DATA, message: "Could not parse X.509 key: \(errStr)", nativeStack: nil)
        }
        
        return .success((algorithm: algorithm, publicKey: publicKey))
    }
    
    // MARK: - ASN.1 DER Transcoder
    
    // Evaluates EC signatures and converts raw IEEE P1363 arrays into standard ASN.1 DER sequences.
    private func ensureDerSignature(signatureData: Data, algorithm: VerifyAlgorithms) -> SiliconResult<Data> {
        var expectedP1363DataCount: Int
        
        switch algorithm {
        case .ES256: expectedP1363DataCount = 64 // 256 / 8 * 2 = 64 Bytes
        case .ES384: expectedP1363DataCount = 96 // 384 / 8 * 2 = 96 Bytes
        case .ES512: expectedP1363DataCount = 132 // 521 / 8 = 65.125 (round up) 66 * 2 = 132 Bytes
        default:
            return .failure(
                code: .INTERNAL_ERROR,
                message: "verify: unexpected algorithm (\(algorithm.rawValue)) when attempting to ensure ASN.1 DER signature.",
                nativeStack: nil
            )
        }
        
        // If the signature matches the exact data count, it is P1363, else DER
        let isRawP1363 = signatureData.count == expectedP1363DataCount
        
        if !isRawP1363 {
            // Signature should already be DER
            guard signatureData.first == 0x30 else {
                return .failure(
                    code: .MALFORMED_DATA,
                    message: "Signature did not start with DER Sequence tag (0x30).",
                    nativeStack: nil
                )
            }
            return .success(signatureData)
        }
        
        let halfLen = signatureData.count / 2
        let rBytes = signatureData.subdata(in: 0..<halfLen)
        let sBytes = signatureData.subdata(in: halfLen..<signatureData.count)
        
        let rDer = encodeDerInteger(rBytes)
        let sDer = encodeDerInteger(sBytes)
        
        let payloadLen = 2 + rDer.count + 2 + sDer.count
        
        var der = Data()
        der.append(0x30) // Sequence Tag
        
        if payloadLen >= 128 {
            der.append(0x81) // Long-form length marker
            der.append(UInt8(payloadLen))
        } else {
            der.append(UInt8(payloadLen))
        }
        
        // Write R
        der.append(0x02) // Integer Tag
        der.append(UInt8(rDer.count))
        der.append(rDer)
        
        // Write S
        der.append(0x02) // Integer Tag
        der.append(UInt8(sDer.count))
        der.append(sDer)
        
        return .success(der)
    }
    
    // Strips leading zeros, but prepends 0x00 if the Most Significant Bit is >= 0x80.
    private func encodeDerInteger(_ bytes: Data) -> Data {
        var index = 0
        
        // Find the first non-zero byte (leave at least 1 byte if all zeros)
        while index < bytes.count - 1 && bytes[index] == 0x00 {
            index += 1
        }
        
        let result = bytes.subdata(in: index..<bytes.count)
        
        // If the MSB is high, ASN.1 requires a leading 0x00 so it isn't parsed as a negative number
        if let first = result.first, (first & 0x80) != 0 {
            var padded = Data([0x00])
            padded.append(result)
            return padded
        }
        
        return result
    }
}
