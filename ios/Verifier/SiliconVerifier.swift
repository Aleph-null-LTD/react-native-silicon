import Foundation
import Security

struct SiliconVerifier {
    static func verify(payload: PayloadType, signatureB64: String, opts: VerifyOptions) throws -> SiliconResult<Bool> {
        let publicKey: SecKey
        var algorithm: VerifyAlgorithms
        
        // Resolve the Public Key
        if let alias = opts.alias, !alias.isEmpty { // Internal key was requested
            let internalKeyResult = try extractInternalKey(alias: alias, opts: opts)
            
            switch internalKeyResult {
            case .success(let internalKey):
                publicKey = internalKey.publicKey
                algorithm = internalKey.algorithm
            case .failure(let code, let message, let nativeStack):
                return .failure(code: code, message: message, nativeStack: nativeStack)
            }
            
        } else if let pubkeyB64 = opts.pubkey, !pubkeyB64.isEmpty { // External key was supplied
            let externalKeyResult = try extractExternalKey(pubkeyB64: pubkeyB64, opts: opts)
            
            switch externalKeyResult {
            case .success(let externalKey):
                publicKey = externalKey.publicKey
                algorithm = externalKey.algorithm
            case .failure(let code, let message, let nativeStack):
                return .failure(code: code, message: message, nativeStack: nativeStack)
            }
            
        } else {
            return .failure(code: "INVALID_PARAMS", message: "Either 'alias' or 'pubkey' must be supplied", nativeStack: nil)
        }
        
        let payloadData: Data
        switch payload {
        case .text(let str):
            guard let rawBytes = str.data(using: .utf8) else {
                return .failure(code: "VERIFY_FAILED", message: "Failed to convert payload to raw bytes", nativeStack: nil)
            }
            payloadData = rawBytes
            
        case .byteArr(let rawBytes):
                payloadData = rawBytes
        }
        
        guard let signatureData = Data(base64Encoded: signatureB64) else {
            return .failure(code: "INVALID_SIG_B64", message: "Could not decode signature", nativeStack: nil)
        }
        
        // Ensure DER Formatting
        let derSignature: Data
        do {
            derSignature = try ensureDerSignature(signatureData: signatureData)
        } catch {
            return .failure(code: "MALFORMED_SIGNATURE", message: error.localizedDescription, nativeStack: nil)
        }
        
        // Determine the SecKey algorithm
        var secKeyAlg: SecKeyAlgorithm
        switch algorithm {
        // Elliptic Curve DSA (ECDSA)
        case .ES256: secKeyAlg = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        case .ES384: secKeyAlg = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384
        case .ES512: secKeyAlg = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512
        
        // RSA PKCS#1 v1.5
        case .RS256: secKeyAlg = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
        case .RS384: secKeyAlg = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA384
        case .RS512: secKeyAlg = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA512
            
        // RSA PSS
        case .PS256: secKeyAlg = SecKeyAlgorithm.rsaSignatureMessagePSSSHA256
        case .PS384: secKeyAlg = SecKeyAlgorithm.rsaSignatureMessagePSSSHA384
        case .PS512: secKeyAlg = SecKeyAlgorithm.rsaSignatureMessagePSSSHA512
        }
        
        // Hardware/OS Verification
        var verifyError: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(
            publicKey,
            secKeyAlg,
            payloadData as CFData,
            derSignature as CFData,
            &verifyError
        )
        
        return .success(isValid)
    }
    
    // MARK: - Internal Keys
    private static func extractInternalKey(alias: String, opts: VerifyOptions) throws -> SiliconResult<(algorithm: VerifyAlgorithms, publicKey: SecKey)> {
        var algorithm: VerifyAlgorithms
        
        // Fetch from local Keychain
        guard let tag = alias.data(using: .utf8) else {
            return .failure(code: "INVALID_ALIAS", message: "Alias could not be encoded", nativeStack: nil)
        }
        
        // Get the key metadata
        guard let metadata = try? KeyMetadataStore.get(alias: alias) else {
            return .failure(code: "VERIFY_FAILED", message: "Error getting key metadata", nativeStack: nil)
        }
        
        // Ensure the key has the VERIFY purpose
        if !metadata.purposes.contains(KeyPurpose.VERIFY) {
            return .failure(code: "INVALID_PURPOSE", message: "Key does not have the VERIFY purpose", nativeStack: nil)
        }
        
        guard let allowedDigests = metadata.digests else {
            return .failure(code: "VERIFY_FAILED", message: "Key metadata does not have a digests array", nativeStack: nil)
        }
        
        // Query keychain for the key
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnAttributes as String: true, // Gets Metadata dict for the key
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            return .failure(code: "KEY_NOT_FOUND", message: "Local key alias '\(alias)' missing", nativeStack: nil)
        }
        
        guard let dict = item as? [String: Any] else {
            return .failure(code: "VERIFY_FAILED", message: "Failed to read public key attributes", nativeStack: nil)
        }
        
        // Extract the SecKey ref
        guard let rawRef = dict[kSecValueRef as String] else {
            return .failure(code: "KEY_FETCH_FAILED", message: "Could not locate SecKey reference in dictionary", nativeStack: nil)
        }
        let keyRef = rawRef as! SecKey
        
        // Extract the public key from the SecKey reference
        guard let publicKey = SecKeyCopyPublicKey(keyRef) else {
            return .failure(code: "NO_CERT", message: "Could not extract public key from Keychain", nativeStack: nil)
        }
        
        // Get the key size in bits
        guard let keySize = dict[kSecAttrKeySizeInBits as String] as? Int else {
            return .failure(code: "VERIFY_FAILED", message: "Failed to read public key size", nativeStack: nil)
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
            throw SiliconException(
                code: "KEY_TYPE_COERCE_ERROR",
                message: "iOS: rawKeyType was an unexpected type: got '\(String(describing: type(of: keyType)))' expected 'String | Int'"
            )
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
                            code: "INVALID_PARAMETER",
                            message: "iOS: key (\(alias)) is an EC key and must use the algorithm that matches it's size (\(VerifyAlgorithms.ES256.rawValue))",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA256
                case .ES384:
                    if keySize != 384 {
                        return .failure(
                            code: "INVALID_PARAMETER",
                            message: "iOS: key (\(alias)) is an EC key and must use the algorithm that matches it's size (\(VerifyAlgorithms.ES384.rawValue))",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA384
                case .ES512:
                    if keySize != 512 {
                        return .failure(
                            code: "INVALID_PARAMETER",
                            message: "iOS: key (\(alias)) is an EC key and must use the algorithm that matches it's size (\(VerifyAlgorithms.ES512.rawValue))",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA512
                default:
                    return .failure(code: "INVALID_PARAMETER", message: "Cannot use \(safeAlgorithm) with a non-EC key", nativeStack: nil)
                }
                
            } else if keyType == (kSecAttrKeyTypeRSA as String) {
                guard let safeSigPaddingAlg = metadata.signaturePaddingAlgorithm else {
                    throw SiliconException(
                        code: "BAD_METADATA",
                        message: "Metadata did not contain signaturePaddingAlgorithm when attempting verify with RSA key"
                    )
                }
                
                switch safeAlgorithm {
                case .RS256:
                    if safeSigPaddingAlg != .PKCS1 {
                        return .failure(
                            code: "INVALID_ALGORITHM_PARAMETER",
                            message: "Cannot use \(safeSigPaddingAlg.rawValue) padding with key (\(alias)). Please use \(SignaturePaddingAlgorithm.PKCS1.rawValue)",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA256
                case .RS384:
                    if safeSigPaddingAlg != .PKCS1 {
                        return .failure(
                            code: "INVALID_ALGORITHM_PARAMETER",
                            message: "Cannot use \(safeSigPaddingAlg.rawValue) padding with key (\(alias)). Please use \(SignaturePaddingAlgorithm.PKCS1.rawValue)",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA384
                case .RS512:
                    if safeSigPaddingAlg != .PKCS1 {
                        return .failure(
                            code: "INVALID_ALGORITHM_PARAMETER",
                            message: "Cannot use \(safeSigPaddingAlg.rawValue) padding with key (\(alias)). Please use \(SignaturePaddingAlgorithm.PKCS1.rawValue)",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA512
                case .PS256:
                    if safeSigPaddingAlg != .PSS {
                        return .failure(
                            code: "INVALID_ALGORITHM_PARAMETER",
                            message: "Cannot use \(safeSigPaddingAlg.rawValue) padding with key (\(alias)). Please use \(SignaturePaddingAlgorithm.PSS.rawValue)",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA256
                case .PS384:
                    if safeSigPaddingAlg != .PSS {
                        return .failure(
                            code: "INVALID_ALGORITHM_PARAMETER",
                            message: "Cannot use \(safeSigPaddingAlg.rawValue) padding with key (\(alias)). Please use \(SignaturePaddingAlgorithm.PSS.rawValue)",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA384
                case .PS512:
                    if safeSigPaddingAlg != .PSS {
                        return .failure(
                            code: "INVALID_ALGORITHM_PARAMETER",
                            message: "Cannot use \(safeSigPaddingAlg.rawValue) padding with key (\(alias)). Please use \(SignaturePaddingAlgorithm.PSS.rawValue)",
                            nativeStack: nil
                        )
                    }
                    digest = .SHA512
                default:
                    return .failure(code: "INVALID_ALGORITHM_PARAMETER", message: "Cannot use \(safeAlgorithm) with a non-RSA key", nativeStack: nil)
                }
                
            } else {
                return .failure(
                    code: "UNSUPPORTED_KEY_FAMILY",
                    message: "Key (\(alias)) cannot be used for verify",
                    nativeStack: nil
                )
            }
            
            // Ensure the digest is in the list of allowed digests
            if (!allowedDigests.contains(digest)) {
                return .failure(
                    code: "DISALLOWED_DIGEST",
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
                    return .failure(code: "UNSUPPORTED_KEY_FAMILY", message: "Verify does not support key size (\(keySize))", nativeStack: nil)
                }
                
            } else if keyType == (kSecAttrKeyTypeRSA as String) {
                // Key is RSA
                guard let safeSigPaddingAlg = metadata.signaturePaddingAlgorithm else {
                    throw SiliconException(
                        code: "BAD_METADATA",
                        message: "Metadata did not contain signaturePaddingAlgorithm when attempting verify with RSA key"
                    )
                }
                
                switch keySize {
                case 2048:
                    switch safeSigPaddingAlg {
                    case .PKCS1:
                        attemptAlgorithm = .RS256
                    case .PSS:
                        attemptAlgorithm = .PS256
                    }
                    digest = .SHA256
                case 3072:
                    switch safeSigPaddingAlg {
                    case .PKCS1:
                        attemptAlgorithm = .RS384
                    case .PSS:
                        attemptAlgorithm = .PS384
                    }
                    digest = .SHA384
                case 4096:
                    switch safeSigPaddingAlg {
                    case .PKCS1:
                        attemptAlgorithm = .RS512
                    case .PSS:
                        attemptAlgorithm = .PS512
                    }
                    digest = .SHA512
                default:
                    return .failure(code: "UNSUPPORTED_KEY_FAMILY", message: "Verify does not support key size (\(keySize))", nativeStack: nil)
                }
                
            } else {
                return .failure(code: "UNSUPPORTED_KEY_FAMILY", message: "Key family (\(keyType)) is not supported for Verify", nativeStack: nil)
            }
            
            // Check if the digest is in the list of allowed digests
            if (allowedDigests.contains(digest)) {
                algorithm = attemptAlgorithm
            } else {
                return .failure(
                    code: "VERIFY_FAILED",
                    message: "Could not use default verify algorithm for key (\(alias)). Please set the algorithm explicitly in the options.",
                    nativeStack: nil
                )
            }
        }
        
        return .success((algorithm: algorithm, publicKey: publicKey))
    }
    
    // MARK: - External Keys
    private static func extractExternalKey(pubkeyB64: String, opts: VerifyOptions) throws -> SiliconResult<(algorithm: VerifyAlgorithms, publicKey: SecKey)> {
        var algorithm: VerifyAlgorithms
        
        // Parse from External X.509 Base64
        guard let keyData = Data(base64Encoded: pubkeyB64, options: .ignoreUnknownCharacters) else {
            return .failure(code: "INVALID_KEY_B64", message: "Could not decode Base64 public key", nativeStack: nil)
        }
        
        guard let safeAlgorithm = opts.algorithm else {
            throw SiliconException(
                code: "INVALID_PARAM",
                message: "iOS: opts.algorithm was null"
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
        guard let publicKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
            let errStr = error?.takeRetainedValue().localizedDescription ?? "Unknown parse error"
            return .failure(code: "INVALID_PUBKEY", message: "Could not parse X.509 key: \(errStr)", nativeStack: nil)
        }
        
        return .success((algorithm: algorithm, publicKey: publicKey))
    }
    
    // MARK: - ASN.1 DER Transcoder
    
    // Evaluates EC signatures and converts raw IEEE P1363 arrays into standard ASN.1 DER sequences.
    private static func ensureDerSignature(signatureData: Data) throws -> Data {
        let isRawP1363 = signatureData.count == 64 // Assuming ES256 P1363 flat array
        
        if !isRawP1363 {
            guard signatureData.first == 0x30 else {
                throw NSError(domain: "Silicon", code: 0, userInfo: [NSLocalizedDescriptionKey: "Signature did not start with DER Sequence tag (0x30)"])
            }
            return signatureData
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
        
        return der
    }
    
    // Strips leading zeros, but prepends 0x00 if the Most Significant Bit is >= 0x80.
    private static func encodeDerInteger(_ bytes: Data) -> Data {
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
