import Security
import Foundation

struct SiliconJose {
    private var keyMetadataStore: KeyMetadataStoring
    private var pubKeyData: PubKeyData
    
    init(keyMetadataStore: KeyMetadataStoring, pubKeyData: PubKeyData) {
        self.keyMetadataStore = keyMetadataStore
        self.pubKeyData = pubKeyData
    }
    
    func getJwk(alias: String, digest: KeyDigests?) -> SiliconResult<[String: Any]> {
        do {
            // Get the pubkey
            let pubkey = try pubKeyData.queryKeychain(alias: alias)
            
            // Get the key size in bits
            guard let keySize = pubkey.dict[kSecAttrKeySizeInBits as String] as? Int else {
                return .failure(code: .GET_JWK_FAILED, message: "Failed to read public key attributes.", nativeStack: nil)
            }
            
            // Get the key type and safely coerce it
            let rawKeyType = pubkey.dict[kSecAttrKeyType as String]
            let keyType: String
            if let typeNum = rawKeyType as? NSNumber {
                // If it's a number, convert it to a string
                keyType = typeNum.stringValue
            } else if let typeStr = rawKeyType as? String {
                // If it's already a string, keep it
                keyType = typeStr
            } else {
                return .failure(
                    code: .GET_JWK_FAILED,
                    message: "rawKeyType was an unexpected type: got '\(String(describing: type(of: keyType)))' expected 'String | Int'",
                    nativeStack: nil
                )
            }
        
            // Route to the correct JWK constructor
            let jwk: [String: Any]
            
            if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) || keyType == (kSecAttrKeyTypeEC as String) {
                // EC keys
                let constructResult = constructEcJwk(rawData: pubkey.rawData, keySize: keySize, digest: digest)
                
                switch constructResult {
                case .failure(let code, let message, let nativeStack):
                    return .failure(code: code, message: message, nativeStack: nativeStack)
                case .success(let constructedJwk):
                    jwk = constructedJwk
                }
                
            } else if keyType == (kSecAttrKeyTypeRSA as String) {
                // RSA keys
                do {
                    let metadata = try keyMetadataStore.get(alias: alias)
                    
                    guard let sigPadAlg = metadata.signaturePaddingAlgorithm else {
                        return .failure(
                            code: .GET_JWK_FAILED,
                            message: "No signature padding algorithm was found in the metadata for key (\(alias))",
                            nativeStack: nil
                        )
                    }
                    
                    let isPSS = sigPadAlg == .PSS
                    
                    let constructResult = constructRsaJwk(rawData: pubkey.rawData, keySize: keySize, isPSS: isPSS, digest: digest)
                    
                    switch constructResult {
                    case .failure(let code, let message, let nativeStack):
                        return .failure(code: code, message: message, nativeStack: nativeStack)
                    case .success(let constructedJwk):
                        jwk = constructedJwk
                    }
                    
                } catch {
                    return .failure(
                        code: .GET_JWK_FAILED,
                        message: error.localizedDescription,
                        nativeStack: nil
                    )
                }
                
            } else {
                return .failure(code: .UNSUPPORTED, message: "Key family \(keyType) is not supported for JWK", nativeStack: nil)
            }
            return .success(jwk)
            
        } catch let error as GetPubKeyDataError {
            var code: SiliconErrorCode
            switch error {
            case .invalidAlias:
                code = .INVALID_ARGUMENT
            case .keyNotFound:
                code = .KEY_NOT_FOUND
            case .unsupportedKeyFamily:
                code = .UNSUPPORTED
            default:
                code = .GET_JWK_FAILED
            }
            return .failure(code: code, message: error.localizedDescription, nativeStack: nil)
            
        } catch {
            return .failure(code: .GET_JWK_FAILED, message: error.localizedDescription, nativeStack: nil)
        }
    }

    // MARK: - EC Construction
    private func constructEcJwk(rawData: Data, keySize: Int, digest: KeyDigests?) -> SiliconResult<[String: Any]> {
        // Apple's EC External Representation is ANSI X9.63 format: 0x04 || X || Y
        guard rawData.first == 0x04 else {
            return .failure(
                code: .GET_JWK_FAILED,
                message: "Invalid EC public key format.",
                nativeStack: nil
            )
        }
        
        let coordinateLength = (keySize + 7) / 8 // 256 bits = 32 bytes
        guard rawData.count == 1 + (2 * coordinateLength) else {
            return .failure(
                code: .GET_JWK_FAILED,
                message: "EC key byte length mismatch.",
                nativeStack: nil
            )
        }
        
        let xData = rawData[1 ... coordinateLength]
        let yData = rawData[(1 + coordinateLength) ... (2 * coordinateLength)]
        
        let (alg, crv): (String, String)
        switch keySize {
        case 256:
            if digest != nil && digest != .SHA256 {
                return .failure(
                    code: .INCOMPATIBLE,
                    message: "\(KeyAlgorithm.EC_P256.rawValue) keys must use the \(KeyDigests.SHA256.rawValue) digest.",
                    nativeStack: nil
                )
            }
            (alg, crv) = ("ES256", "P-256")
        case 384:
            if digest != nil && digest != .SHA384 {
                return .failure(
                    code: .INCOMPATIBLE,
                    message: "\(KeyAlgorithm.EC_P384.rawValue) keys must use the \(KeyDigests.SHA384.rawValue) digest.",
                    nativeStack: nil
                )
            }
            (alg, crv) = ("ES384", "P-384")
        case 521:
            if digest != nil && digest != .SHA512 {
                return .failure(
                    code: .INCOMPATIBLE,
                    message: "\(KeyAlgorithm.EC_P521.rawValue) keys must use the \(KeyDigests.SHA512.rawValue) digest.",
                    nativeStack: nil
                )
            }
            (alg, crv) = ("ES512", "P-521")
        default:
            return .failure(
                code: .UNSUPPORTED,
                message: "Unsupported EC curve size: \(keySize)",
                nativeStack: nil
            )
        }
        
        return .success([
            "kty": "EC",
            "crv": crv,
            "x": base64URLEncode(xData),
            "y": base64URLEncode(yData),
            "alg": alg
        ])
    }

    // MARK: - RSA Construction
    private func constructRsaJwk(rawData: Data, keySize: Int, isPSS: Bool, digest: KeyDigests?) -> SiliconResult<[String: Any]> {
        // rawData is ASN.1 DER encoded: SEQUENCE { INTEGER n, INTEGER e }
        guard let (nData, eData) = extractRSADerComponents(der: rawData) else {
            return .failure(
                code: .MALFORMED_DATA,
                message: "Failed to parse RSA ASN.1 structure.",
                nativeStack: nil
            )
        }
        
        // Determine the algorithm
        let alg: String
        if let requestedDigest = digest {
            // Digest was explicitly set so use the corresponding algorithm
            switch requestedDigest {
            case .SHA256: alg = isPSS ? "PS256" : "RS256"
            case .SHA384: alg = isPSS ? "PS384" : "RS384"
            case .SHA512: alg = isPSS ? "PS512" : "RS512"
            }
        } else {
            // Digest was not set so use the algorithm that matches the key size
            // This corresponds to the same default algorithms we use when signing/verifying
            // RSA keys can be -1 below the expected size
            if keySize >= 4095 {
                alg = isPSS ? "PS512" : "RS512"
            } else if keySize >= 3073 {
                alg = isPSS ? "PS384" : "RS384"
            } else if keySize >= 2047 {
                alg = isPSS ? "PS256" : "RS256"
            } else {
                return .failure(
                    code: .UNSUPPORTED,
                    message: "RSA key size \(keySize) is not supported for this function.",
                    nativeStack: nil
                )
            }
        }

        return .success([
            "kty": "RSA",
            "n": base64URLEncode(nData),
            "e": base64URLEncode(eData),
            "alg": alg
        ])
    }

    // MARK: - Helpers

    /// ASN.1 byte scanner to extract `n` and `e` from an RSA Public Key DER structure.
    private func extractRSADerComponents(der: Data) -> (n: Data, e: Data)? {
        var index = 0
        func readLength() -> Int? {
            guard index < der.count else { return nil }
            let first = der[index]; index += 1
            if first < 128 { return Int(first) } // Short form
            let lengthBytesCount = Int(first & 0x7F)
            guard index + lengthBytesCount <= der.count else { return nil }
            var length = 0
            for _ in 0..<lengthBytesCount {
                length = (length << 8) + Int(der[index]); index += 1
            }
            return length
        }
        
        // SEQUENCE
        guard index < der.count, der[index] == 0x30 else { return nil }
        index += 1
        guard readLength() != nil else { return nil }
        
        // Modulus (n)
        guard index < der.count, der[index] == 0x02 else { return nil }
        index += 1
        guard let nLength = readLength(), index + nLength <= der.count else { return nil }
        var nData = der[index..<(index + nLength)]
        index += nLength
        if nData.first == 0x00 { nData = nData.dropFirst() } // Strip rogue leading zero
        
        // Exponent (e)
        guard index < der.count, der[index] == 0x02 else { return nil }
        index += 1
        guard let eLength = readLength(), index + eLength <= der.count else { return nil }
        let eData = der[index..<(index + eLength)]
        
        return (nData, eData)
    }
}
