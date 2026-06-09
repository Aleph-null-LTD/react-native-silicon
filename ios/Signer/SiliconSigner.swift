import Security
import Foundation
import LocalAuthentication

struct SiliconSigner {
    static func sign(alias: String, payload: PayloadType, opts: SignOptions) async -> SiliconResult<String> {
        guard let tag = alias.data(using: .utf8) else {
            return .failure(code: .INVALID_ARGUMENT, message: "Failed to encode alias.", nativeStack: nil)
        }
        
        // Get the key metadata
        guard let metadata = try? KeyMetadataStore.get(alias: alias) else {
            return .failure(code: .SIGN_FAILED, message: "Failed to read key metadata.", nativeStack: nil)
        }
        
        if !metadata.purposes.contains(KeyPurpose.SIGN) {
            return .failure(
                code: .KEY_POLICY_VIOLATION,
                message: "Key (\(alias)) does not have the SIGN purpose.",
                nativeStack: nil
            )
        }
        
        guard let allowedDigests = metadata.digests else {
            return .failure(code: .INTERNAL_ERROR, message: "No allowed digests in key metadata.", nativeStack: nil)
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
            return .failure(code: .KEY_NOT_FOUND, message: "No key found for alias \(alias)", nativeStack: nil)
        }
        
        guard status == errSecSuccess,
              let dict = item as? [String: Any],
              let privateKey = dict[kSecValueRef as String] as! SecKey? else {
            
            if status == errSecUserCanceled {
                return .failure(code: .AUTH_CANCELED, message: "User canceled authentication.", nativeStack: nil)
            } else if status == errSecAuthFailed {
                return handleAuthFailed(context: context, keyMetadata: metadata)
            }
            
            return .failure(code: .SIGN_FAILED, message: "Keychain lookup failed with OSStatus: \(status)", nativeStack: nil)
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
            return .failure(
                code: .SIGN_FAILED,
                message: "rawKeyType had an unexpected type: got \(String(describing: type(of: keyType))) expected String | Int",
                nativeStack: nil
            )
        }
        
        guard let keySize = dict[kSecAttrKeySizeInBits as String] as? Int else {
            return .failure(
                code: .SIGN_FAILED,
                message: "Unable to read key size from kSecAttrKeySizeInBits.",
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
                        code: .KEY_POLICY_VIOLATION,
                        message: "Requested digest \(requestedDigest) is not in the list of allowed digests for key \(alias).",
                        nativeStack: nil
                    )
                }
                
                switch requestedDigest {
                case .SHA256:
                    if keySize != 256 {
                        return .failure(
                            code: .INCOMPATIBLE,
                            message: "key (\(alias)) is an EC key and must use the digest that matches it's key size (\(KeyDigests.SHA256.rawValue)).",
                            nativeStack: nil
                        )
                    }
                    algorithm = .ecdsaSignatureMessageX962SHA256
                case .SHA384:
                    if keySize != 384 {
                        return .failure(
                            code: .INCOMPATIBLE,
                            message: "key (\(alias)) is an EC key and must use the digest that matches it's key size (\(KeyDigests.SHA384.rawValue)).",
                            nativeStack: nil
                        )
                    }
                    algorithm = .ecdsaSignatureMessageX962SHA384
                case .SHA512:
                    if keySize != 521 {
                        return .failure(
                            code: .INCOMPATIBLE,
                            message: "key (\(alias)) is an EC key and must use the digest that matches it's key size (\(KeyDigests.SHA512.rawValue)).",
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
                        code: .UNSUPPORTED,
                        message: "EC keys with size \(keySize) are not supported for sign.",
                        nativeStack: nil
                    )
                }
                
                if !allowedDigests.contains(defaultDigest) {
                    return .failure(
                        code: .KEY_POLICY_VIOLATION,
                        message: "Cannot use default digest (\(defaultDigest)) for key \(alias) as it is not in the allowed digests list (\(allowedDigests)). Please set it explicitly in the options.",
                        nativeStack: nil
                    )
                }
            }
            isEC = true
            
        } else if keyType == (kSecAttrKeyTypeRSA as String) {
            guard let sigPaddingAlg = metadata.signaturePaddingAlgorithm else {
                return .failure(
                    code: .SIGN_FAILED,
                    message: "Key metadata did not include signaturePaddingAlgorithm.",
                    nativeStack: nil
                )
            }
            
            if let requestedDigest = opts.digest {
                // Ensure the digest is in the key's allowed digests
                if !allowedDigests.contains(requestedDigest) {
                    return .failure(
                        code: .KEY_POLICY_VIOLATION,
                        message: "Requested digest \(requestedDigest) is not in the list of allowed digests for key \(alias).",
                        nativeStack: nil
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
                
                // RSA keys can be -1 below the expected size
                switch keySize {
                case 2048, 2047:
                    switch sigPaddingAlg {
                    case .PKCS1: algorithm = .rsaSignatureMessagePKCS1v15SHA256
                    case .PSS: algorithm = .rsaSignatureMessagePSSSHA256
                    }
                    defaultDigest = .SHA256
                case 3072, 3071:
                    switch sigPaddingAlg {
                    case .PKCS1: algorithm = .rsaSignatureMessagePKCS1v15SHA256
                    case .PSS: algorithm = .rsaSignatureMessagePSSSHA256
                    }
                    defaultDigest = .SHA384
                case 4096, 4095:
                    switch sigPaddingAlg {
                    case .PKCS1: algorithm = .rsaSignatureMessagePKCS1v15SHA256
                    case .PSS: algorithm = .rsaSignatureMessagePSSSHA256
                    }
                    defaultDigest = .SHA512
                default:
                    return .failure(
                        code: .UNSUPPORTED,
                        message: "RSA keys with size \(keySize) are not supported for sign.",
                        nativeStack: nil
                    )
                }
                
                if !allowedDigests.contains(defaultDigest) {
                    return .failure(
                        code: .KEY_POLICY_VIOLATION,
                        message: "Cannot use default digest (\(defaultDigest)) for key \(alias) as it is not in the allowed digests list (\(allowedDigests)). Please set it explicitly in the options.",
                        nativeStack: nil
                    )
                }
            }
            isEC = false
            
        } else {
            return .failure(code: .INCOMPATIBLE, message: "Key with type \(keyType.utf8) cannot be used for signing.", nativeStack: nil)
        }
        
        // Convert the payload to CFData
        let payloadData: CFData
        
        switch payload {
        case .byteArr(let rawBytes):
            payloadData = rawBytes as CFData
            
        case .text(let payloadStr):
            guard let rawBytes = payloadStr.data(using: .utf8) else {
                return .failure(code: .MALFORMED_DATA, message: "payloadStr could not be converted to UTF8 Data", nativeStack: nil)
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
            if errCode == errSecUserCanceled {
                return .failure(code: .AUTH_CANCELED, message: "User canceled authentication.", nativeStack: nil)
            } else if errCode == errSecAuthFailed {
                return handleAuthFailed(context: context, keyMetadata: metadata)
            }
            
            return .failure(code: .SIGN_FAILED, message: err?.localizedDescription ?? "Unknown signing error", nativeStack: nil)
        }
        
        
        var finalSignature = signatureData
        
        if isEC {
            if opts.format == .P1363 {
                // Transcode DER to P1363
                do {
                    // e.g., 256 bits / 8 = 32 bytes per coordinate
                    let targetCoordSize = (keySize + 7) / 8
                    finalSignature = try transcodeDerToP1363(derSignature: signatureData, targetSize: targetCoordSize)
                } catch {
                    return .failure(code: .SIGN_FAILED, message: "Failed to transcode DER signature to P1363.", nativeStack: nil)
                }
            } else if opts.format == .DER {
                // Do nothing (signature is already DER)
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
    
    // MARK: - Helpers
    private static func handleAuthFailed(context: LAContext, keyMetadata: KeyMetadata) -> SiliconResult<String> {
        var authError: NSError?
        
        context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError)
        
        if let error = authError {
            let laError = LAError(_nsError: error)
                    
            switch laError.code {
            case .biometryLockout:
                // The user failed 5 times. The sensor is disabled.
                return .failure(
                    code: .AUTH_LOCKED_OUT,
                    message: "Too many failed attempts. Biometrics are locked and require the device passcode to re-enable.",
                    nativeStack: nil
                )
                
            case .biometryNotEnrolled:
                return .failure(
                    code: .BIOMETRICS_NOT_ENROLLED,
                    message: "Biometrics are not enrolled on this device.",
                    nativeStack: nil
                )
                
            case .biometryNotAvailable:
                return .failure(
                    code: .BIOMETRICS_NOT_AVAILABLE,
                    message: "Biometrics are not enrolled on this device.",
                    nativeStack: nil
                )
                
            case .passcodeNotSet:
                return .failure(
                    code: .NO_PASSCODE,
                    message: "Passcode is not set on this device.",
                    nativeStack: nil
                )
                
            case .systemCancel, .appCancel, .userCancel:
                return .failure(
                    code: .AUTH_CANCELED,
                    message: "Authentication was canceled.",
                    nativeStack: nil
                )
                
            default:
                break // Some other LAError, continue
            }
        }
        
        // context.evaluatedPolicyDomainState will be nil if the user is currently locked out
        if let currentDomainState = context.evaluatedPolicyDomainState {
            if keyMetadata.userAuthInvalidateOnEnrollment &&
                keyMetadata.userAuthDomainState != nil &&
                currentDomainState != keyMetadata.userAuthDomainState
            {
                return .failure(code: .KEY_INVALIDATED, message: "Key was invalidated due to new biometrics enrollment.", nativeStack: nil)
            }
        }
        
        return .failure(code: .AUTH_FAILED, message: "Authentication failed", nativeStack: nil)
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
