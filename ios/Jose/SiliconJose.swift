import Security
import Foundation

struct SiliconJose {
    static func getJwk(alias: String) -> SiliconResult<[String: Any]> {
        do {
            // Get the pubkey
            let pubkey = try getPubKeyData(alias: alias)
            
            // Get the key size in bits
            guard let keySize = pubkey.dict[kSecAttrKeySizeInBits as String] as? Int else {
                return .failure(code: "GET_JWK_FAILED", message: "Failed to read public key attributes.", nativeStack: nil)
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
                throw SiliconException(
                    code: "KEY_TYPE_COERCE_ERROR",
                    message: "iOS: rawKeyType was an unexpected type: got '\(String(describing: type(of: keyType)))' expected 'String | Int'"
                )
            }
        
            // Route to the correct JWK constructor
            let jwk: [String: Any]
            if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) || keyType == (kSecAttrKeyTypeEC as String) {
                jwk = try constructEcJwk(rawData: pubkey.rawData, keySize: keySize)
            } else if keyType == (kSecAttrKeyTypeRSA as String) {
                jwk = try constructRsaJwk(rawData: pubkey.rawData, keySize: keySize)
            } else {
                return .failure(code: "UNSUPPORTED_KEY_FAMILY", message: "Key family is not supported for JWK", nativeStack: nil)
            }
            return .success(jwk)
            
        } catch let error as GetPubKeyDataError {
            var code: String
            switch error {
            case .invalidAlias:
                code = "INVALID_ALIAS"
            case .keyNotFound:
                code = "KEY_NOT_FOUND"
            case .unsupportedKeyFamily:
                code = "UNSUPPORTED_KEY_FAMILY"
            default:
                code = "GET_JWK_FAILED"
            }
            return .failure(code: code, message: error.localizedDescription, nativeStack: nil)
            
        } catch {
            return .failure(code: "GET_JWK_FAILED", message: error.localizedDescription, nativeStack: nil)
        }
    }

    // MARK: - EC Construction
    private static func constructEcJwk(rawData: Data, keySize: Int) throws -> [String: Any] {
        // Apple's EC External Representation is ANSI X9.63 format: 0x04 || X || Y
        guard rawData.first == 0x04 else {
            throw NSError(domain: "Silicon", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid EC public key format."])
        }
        
        let coordinateLength = (keySize + 7) / 8 // 256 bits = 32 bytes
        guard rawData.count == 1 + (2 * coordinateLength) else {
            throw NSError(domain: "Silicon", code: 0, userInfo: [NSLocalizedDescriptionKey: "EC key byte length mismatch."])
        }
        
        let xData = rawData[1 ... coordinateLength]
        let yData = rawData[(1 + coordinateLength) ... (2 * coordinateLength)]
        
        let (alg, crv): (String, String)
        switch keySize {
            case 256: (alg, crv) = ("ES256", "P-256")
            case 384: (alg, crv) = ("ES384", "P-384")
            case 521: (alg, crv) = ("ES512", "P-521")
            default: throw NSError(domain: "Silicon", code: 0, userInfo: [NSLocalizedDescriptionKey: "Unsupported EC curve size: \(keySize)"])
        }
        
        return [
            "kty": "EC",
            "crv": crv,
            "x": base64URLEncode(xData),
            "y": base64URLEncode(yData),
            "alg": alg
        ]
    }

    // MARK: - RSA Construction
    private static func constructRsaJwk(rawData: Data, keySize: Int) throws -> [String: Any] {
        // rawData is ASN.1 DER encoded: SEQUENCE { INTEGER n, INTEGER e }
        guard let (nData, eData) = extractRSADerComponents(der: rawData) else {
            throw NSError(domain: "Silicon", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to parse RSA ASN.1 structure."])
        }
        
        let alg: String
        if keySize >= 4096 { alg = "RS512" }
        else if keySize >= 3072 { alg = "RS384" }
        else if keySize >= 2048 { alg = "RS256" }
        else { throw NSError(domain: "Silicon", code: 0, userInfo: [NSLocalizedDescriptionKey: "RSA key size \(keySize) is too weak."]) }
        
        return [
            "kty": "RSA",
            "n": base64URLEncode(nData),
            "e": base64URLEncode(eData),
            "alg": alg
        ]
    }

    // MARK: - Helpers

    /// ASN.1 byte scanner to extract `n` and `e` from an RSA Public Key DER structure.
    private static func extractRSADerComponents(der: Data) -> (n: Data, e: Data)? {
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
