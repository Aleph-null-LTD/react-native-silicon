import Foundation
import Security

struct SiliconVerifier {
    static func verify(payload: PayloadType, signatureB64: String, opts: VerifyOptions) throws -> SiliconResult<Bool> {
        let publicKey: SecKey
        var algorithm: VerifyAlgorithms
        
        // Resolve the Public Key
        if let alias = opts.alias, !alias.isEmpty {
            // Fetch from local Keychain
            guard let tag = alias.data(using: .utf8) else {
                return .failure(code: "INVALID_ALIAS", message: "Alias could not be encoded", nativeStack: nil)
            }
            
            // Get the key metadata
            guard let metadata = KeyMetadata.get(alias: alias) else {
                return .failure(code: "VERIFY_FAILED", message: "Key metadata could not be found", nativeStack: nil)
            }
            
            guard let purposes = metadata["purposes"] as? [String] else {
                return .failure(code: "VERIFY_FAILED", message: "Key purposes were invalid", nativeStack: nil)
            }
            if !purposes.contains(KeyPurpose.VERIFY.rawValue) {
                return .failure(code: "INVALID_PURPOSE", message: "Key does not have the VERIFY purpose", nativeStack: nil)
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
            guard let pubKey = SecKeyCopyPublicKey(keyRef) else {
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
                // Algorithm was explicitly provided, so ensure it is compatible with the key family
                switch safeAlgorithm {
                case .ES256, .ES384, .ES512:
                    if keyType != (kSecAttrKeyTypeECSECPrimeRandom as String) && keyType != (kSecAttrKeyTypeEC as String) {
                        return .failure(code: "INVALID_ALGORITHM_PARAMETER", message: "Attempted to use \(safeAlgorithm) with a non-EC key", nativeStack: nil)
                    }
                    
                case .RS256, .RS384, .RS512, .PS256, .PS384, .PS512:
                    if keyType != (kSecAttrKeyTypeRSA as String) {
                        return .failure(code: "INVALID_ALGORITHM_PARAMETER", message: "Attempted to use \(safeAlgorithm) with a non-RSA key", nativeStack: nil)
                    }
                }
                
                algorithm = safeAlgorithm

            } else {
                // Algorithm was not provided, so determine the algorithm based on the key size and family
                if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) || keyType == (kSecAttrKeyTypeEC as String) {
                    switch keySize {
                    case 256:
                        algorithm = .ES256
                    case 384:
                        algorithm = .ES384
                    case 521:
                        algorithm = .ES512
                    default:
                        return .failure(code: "UNSUPPORTED_KEY_FAMILY", message: "Verify does not support key size (\(keySize))", nativeStack: nil)
                    }
                    
                } else if keyType == (kSecAttrKeyTypeRSA as String) {
                    // TODO: Read the RSA algorithm (PS or RS) from KeyMetadata (we need to store it there when key is generated)
                    
                    switch keySize {
                    case 2048:
                        algorithm = .RS256
                    case 3072:
                        algorithm = .RS384
                    case 4096:
                        algorithm = .RS512
                    default:
                        return .failure(code: "UNSUPPORTED_KEY_FAMILY", message: "Verify does not support key size (\(keySize))", nativeStack: nil)
                    }
                    
                } else {
                    return .failure(code: "UNSUPPORTED_KEY_FAMILY", message: "Key family (\(keyType)) is not supported for Verify", nativeStack: nil)
                }
            }
            
            publicKey = pubKey
            
        } else if let pubkeyB64 = opts.pubkey, !pubkeyB64.isEmpty {
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
            
            var error: Unmanaged<CFError>?
            guard let pubKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
                let errStr = error?.takeRetainedValue().localizedDescription ?? "Unknown parse error"
                return .failure(code: "INVALID_PUBKEY", message: "Could not parse X.509 key: \(errStr)", nativeStack: nil)
            }
            publicKey = pubKey
            
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
        case .RS256: secKeyAlg = SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256
        case .RS384: secKeyAlg = SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA384
        case .RS512: secKeyAlg = SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA512
            
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
