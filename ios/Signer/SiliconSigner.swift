import Security
import Foundation
import LocalAuthentication

struct SiliconSigner {
    static func sign(alias: String, payload: PayloadType, opts: SignOptions) async throws -> SiliconResult<String> {
        guard let tag = alias.data(using: .utf8) else {
            return .failure(code: "INVALID_ALIAS", message: "Failed to encode alias", nativeStack: nil)
        }
        
        // Get the key metadata
        guard let metadata = try? KeyMetadataStore.get(alias: alias) else {
            throw SiliconException(
                code: "SIGN_FAILED",
                message: "iOS: Failed to read key metadata"
            )
        }
        
        if !metadata.purposes.contains(KeyPurpose.SIGN) {
            return .failure(
                code: "DISALLOWED_PURPOSE",
                message: "iOS: Key does not have the SIGN purpose",
                nativeStack: nil
            )
        }
        
        guard let allowedDigests = metadata.digests else {
            throw SiliconException(
                code: "SIGN_FAILED",
                message: "iOS: No allowed digests in key metadata"
            )
        }
        
        // Get the timeout and cast it to Double
        let timeoutSecs = Double(metadata.userAuthTimeout)
        
        var allowsPasscode: Bool
        switch metadata.userAuthPolicy {
        case .BIOMETRICS_ONLY: allowsPasscode = false
        case .BIOMETRICS_OR_CREDENTIAL: allowsPasscode = true
        }
        
        // Get the Context
        let context = AuthContext.get(forTimeout: timeoutSecs, allowsPasscode: allowsPasscode)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true,
            kSecReturnAttributes as String: true,
            kSecUseAuthenticationContext as String: context, // Bind the context
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecItemNotFound {
            return .failure(code: "KEY_NOT_FOUND", message: "No key found for alias: \(alias)", nativeStack: nil)
        }
        
        guard status == errSecSuccess,
              let dict = item as? [String: Any],
              let privateKey = dict[kSecValueRef as String] as! SecKey? else {
            
            // Catch if the user hit "Cancel" on the Face ID prompt during key fetch
            if status == errSecUserCanceled || status == errSecAuthFailed {
                 return .failure(code: "AUTH_CANCELED", message: "User canceled authentication.", nativeStack: nil)
            }
            return .failure(code: "GET_KEY_FAILED", message: "Keychain lookup failed with OSStatus: \(status)", nativeStack: nil)
        }
        
        // Determine Algorithm & Attributes
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
        
        guard let keySize = dict[kSecAttrKeySizeInBits as String] as? Int else {
            return .failure(
                code: "SIGN_FAILED",
                message: "iOS: Unable to read key size from kSecAttrKeySizeInBits",
                nativeStack: nil
            )
        }
        
        let algorithm: SecKeyAlgorithm
        let isEC: Bool
        
        if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) || keyType == (kSecAttrKeyTypeEC as String) {
            if let requestedDigest = opts.digest {
                // Ensure the digest is in the key's allowed digests
                if !allowedDigests.contains(requestedDigest) {
                    return .failure(
                        code: "DISALLOWED_DIGEST",
                        message: "iOS: Requested digest \(requestedDigest) is not in the list of allowed digests for key \(alias)",
                        nativeStack: nil
                    )
                }
                
                switch requestedDigest {
                case .SHA256:
                    if keySize != 256 {
                        return .failure(
                            code: "INVALID_PARAM",
                            message: "iOS: key (\(alias)) is an EC key and must use the digest that matches it's key size (\(KeyDigests.SHA256.rawValue))",
                            nativeStack: nil
                        )
                    }
                    algorithm = .ecdsaSignatureMessageX962SHA256
                case .SHA384:
                    if keySize != 384 {
                        return .failure(
                            code: "INVALID_PARAM",
                            message: "iOS: key (\(alias)) is an EC key and must use the digest that matches it's key size (\(KeyDigests.SHA384.rawValue))",
                            nativeStack: nil
                        )
                    }
                    algorithm = .ecdsaSignatureMessageX962SHA384
                case .SHA512:
                    if keySize != 521 {
                        return .failure(
                            code: "INVALID_PARAM",
                            message: "iOS: key (\(alias)) is an EC key and must use the digest that matches it's key size (\(KeyDigests.SHA512.rawValue))",
                            nativeStack: nil
                        )
                    }
                    algorithm = .ecdsaSignatureMessageX962SHA512
                }
                
            } else {
                var defaultDigest: KeyDigests
                
                switch keySize {
                case 256:
                    algorithm = .ecdsaSignatureMessageX962SHA256
                    defaultDigest = .SHA256
                case 384:
                    algorithm = .ecdsaSignatureMessageX962SHA384
                    defaultDigest = .SHA384
                case 521:
                    algorithm = .ecdsaSignatureMessageX962SHA512
                    defaultDigest = .SHA512
                default:
                    return .failure(
                        code: "NOT_SUPPORTED",
                        message: "iOS: EC keys with size \(keySize) are not supported for sign",
                        nativeStack: nil
                    )
                }
                
                if !allowedDigests.contains(defaultDigest) {
                    return .failure(
                        code: "DISALLOWED_DIGEST",
                        message: "iOS: Cannot use default digest (\(defaultDigest)) for key \(alias) as it is not in the allowed digests list (\(allowedDigests)). Please set it explicitly in the options.",
                        nativeStack: nil
                    )
                }
            }
            isEC = true
            
        } else if keyType == (kSecAttrKeyTypeRSA as String) {
            guard let sigPaddingAlg = metadata.signaturePaddingAlgorithm else {
                return .failure(
                    code: "SIGN_FAILED",
                    message: "iOS: Key metadata did not include signaturePaddingAlgorithm",
                    nativeStack: nil
                )
            }
            
            if let requestedDigest = opts.digest {
                // Ensure the digest is in the key's allowed digests
                if !allowedDigests.contains(requestedDigest) {
                    throw SiliconException(
                        code: "DISALLOWED_DIGEST",
                        message: "iOS: Requested digest \(requestedDigest) is not in the list of allowed digests for key \(alias)"
                    )
                }
                
                switch requestedDigest {
                case .SHA256:
                    switch sigPaddingAlg {
                    case .PKCS1: algorithm = .rsaSignatureMessagePKCS1v15SHA256
                    case .PSS: algorithm = .rsaSignatureMessagePSSSHA256
                    }
                case .SHA384:
                    switch sigPaddingAlg {
                    case .PKCS1: algorithm = .rsaSignatureMessagePKCS1v15SHA384
                    case .PSS: algorithm = .rsaSignatureMessagePSSSHA384
                    }
                case .SHA512:
                    switch sigPaddingAlg {
                    case .PKCS1: algorithm = .rsaSignatureMessagePKCS1v15SHA512
                    case .PSS: algorithm = .rsaSignatureMessagePSSSHA512
                    }
                }
                
            } else {
                var defaultDigest: KeyDigests
                
                switch keySize {
                case 2048:
                    switch sigPaddingAlg {
                    case .PKCS1: algorithm = .rsaSignatureMessagePKCS1v15SHA256
                    case .PSS: algorithm = .rsaSignatureMessagePSSSHA256
                    }
                    defaultDigest = .SHA256
                case 3072:
                    switch sigPaddingAlg {
                    case .PKCS1: algorithm = .rsaSignatureMessagePKCS1v15SHA256
                    case .PSS: algorithm = .rsaSignatureMessagePSSSHA256
                    }
                    defaultDigest = .SHA384
                case 4096:
                    switch sigPaddingAlg {
                    case .PKCS1: algorithm = .rsaSignatureMessagePKCS1v15SHA256
                    case .PSS: algorithm = .rsaSignatureMessagePSSSHA256
                    }
                    defaultDigest = .SHA512
                default:
                    return .failure(
                        code: "NOT_SUPPORTED",
                        message: "iOS: RSA keys with size \(keySize) are not supported for sign",
                        nativeStack: nil
                    )
                }
                
                if !allowedDigests.contains(defaultDigest) {
                    return .failure(
                        code: "DISALLOWED_DIGEST",
                        message: "iOS: Cannot use default digest (\(defaultDigest)) for key \(alias) as it is not in the allowed digests list (\(allowedDigests)). Please set it explicitly in the options.",
                        nativeStack: nil
                    )
                }
            }
            isEC = false
            
        } else {
            return .failure(code: "UNSUPPORTED_KEY_FAMILY", message: "Unsupported key type", nativeStack: nil)
        }
        
        // Convert the payload to CFData
        let payloadData: CFData
        
        switch payload {
        case .byteArr(let rawBytes):
            payloadData = rawBytes as CFData
            
        case .text(let payloadStr):
            guard let rawBytes = payloadStr.data(using: .utf8) else {
                throw SiliconException(
                    code: "PAYLOAD_INVALID",
                    message: "iOS: payloadStr could not be converted to UTF8 Data"
                )
            }
            payloadData = rawBytes as CFData
        }
        
        // Execute Hardware Signature
        // If the key has an Access Control policy, Apple automatically throws the Face ID UI here
        var error: Unmanaged<CFError>?
        guard let signatureData = SecKeyCreateSignature(privateKey, algorithm, payloadData, &error) as Data? else {
            let err = error?.takeRetainedValue()
            let errCode = CFErrorGetCode(err)
            
            // Catch if the user hit "Cancel" during the actual signing operation
            if errCode == errSecUserCanceled || errCode == errSecAuthFailed {
                return .failure(code: "AUTH_CANCELED", message: "User canceled authentication.", nativeStack: nil)
            }
            
            return .failure(code: "SIGNING_FAILED", message: err?.localizedDescription ?? "Unknown signing error", nativeStack: nil)
        }
        
        // Transcode DER to P1363 (Flat Array) for EC Keys
        var finalSignature = signatureData
        if opts.format == .P1363 && isEC {
            do {
                // e.g., 256 bits / 8 = 32 bytes per coordinate
                let targetCoordSize = (keySize + 7) / 8
                finalSignature = try transcodeDerToP1363(derSignature: signatureData, targetSize: targetCoordSize)
            } catch {
                return .failure(code: "TRANSCODING_FAILED", message: "Failed to align signature coordinates.", nativeStack: nil)
            }
        }
        
        // Encode
        let base64Signature: String
        if opts.encoding == .B64URL {
            base64Signature = base64URLEncode(finalSignature)
        } else {
            base64Signature = finalSignature.base64EncodedString()
        }
        
        return .success(base64Signature)
    }

    // MARK: - DER to P1363 Transcoder
    private static func transcodeDerToP1363(derSignature: Data, targetSize: Int) throws -> Data {
        let der = [UInt8](derSignature)
        
        guard der.count > 0, der[0] == 0x30 else {
            throw NSError(domain: "Silicon", code: 0, userInfo: [NSLocalizedDescriptionKey: "Malformed DER signature"])
        }
        
        var offset = 1
        if der[offset] == 0x81 {
            offset += 2
        } else {
            offset += 1
        }
        
        // Extract R
        guard der[offset] == 0x02 else { return derSignature }
        let rLen = Int(der[offset + 1])
        let rStart = offset + 2
        let rBytes = Array(der[rStart..<(rStart + rLen)])
        
        // Extract S
        offset = rStart + rLen
        guard der[offset] == 0x02 else { return derSignature }
        let sLen = Int(der[offset + 1])
        let sStart = offset + 2
        let sBytes = Array(der[sStart..<(sStart + sLen)])
        
        let rAligned = alignCoordinate(bytes: rBytes, targetSize: targetSize)
        let sAligned = alignCoordinate(bytes: sBytes, targetSize: targetSize)
        
        return Data(rAligned + sAligned)
    }

    private static func alignCoordinate(bytes: [UInt8], targetSize: Int) -> [UInt8] {
        if bytes.count == targetSize { return bytes }
        if bytes.count > targetSize {
            // Strip leading zeros
            return Array(bytes.suffix(targetSize))
        } else {
            // Pad with leading zeros
            var padded = [UInt8](repeating: 0, count: targetSize)
            padded.replaceSubrange((targetSize - bytes.count)..<targetSize, with: bytes)
            return padded
        }
    }
}
