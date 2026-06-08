
enum PubKeyFormatError: Error {
    case unsupportedKeyType(type: String)
    case unknownKeySize
    case unsupportedRSASize(size: Int)
    case unsupportedECCurve(size: Int)
    case unknownKeyType(type: String)
    
    var errorDescription: String? {
        switch self {
        case .unknownKeySize:
            return "Failed to determine key size from Keychain attributes."
        case .unsupportedRSASize(let size):
            return "RSA key size \(size) is not supported for X.509 SPKI export. Supported sizes are 2048, 3072, and 4096."
        case .unsupportedECCurve(let size):
            return "EC key size \(size) is not supported. Supported sizes are 256, 384, and 521."
        case .unsupportedKeyType(let type):
            return "Key algorithm not supported for SPKI export. Found value: '\(type)'"
        case .unknownKeyType(let type):
            return "rawKeyType was an unexpected type: got '\(type)' expected String | Int"
        }
    }
}

enum PubKeyType {
    case str(String)
    case data(Data)
}

// Converts the raw ANSI X9.63 key to DER-encoded X.509 SPKI
func pubKeyToX509(format: PubKeyFormat, rawPublicKeyData: Data, rawKeyType: Any?, keySize: Int?) throws -> PubKeyType {
    // Safely coerce the key type
    let keyType: String
    if let typeNum = rawKeyType as? NSNumber {
        // If it's a number, convert it to a string
        keyType = typeNum.stringValue
    } else if let typeStr = rawKeyType as? String {
        // If it's already a string, keep it
        keyType = typeStr
    } else {
        throw PubKeyFormatError.unknownKeyType(type: String(describing: type(of: keyType)))
    }
    
    var uniformPublicKeyBytes = Data()

    // Apply the X.509 SPKI Header to guarantee 1:1 cross-platform byte alignment
    if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
        // Verify the EC key size to apply the correct curve OID header
        guard let size = keySize else {
            throw PubKeyFormatError.unknownKeySize
        }
        
        switch size {
        case 256:
            // NIST P-256 (secp256r1) - Supported by Secure Enclave
            let p256Header = Data([
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
            ])
            uniformPublicKeyBytes.append(p256Header)
            
        case 384:
            // NIST P-384 (secp384r1) - Software Only
            let p384Header = Data([
                0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00
            ])
            uniformPublicKeyBytes.append(p384Header)
            
        case 521: // Note: It is 521, not 512
            // NIST P-521 (secp521r1) - Software Only
            let p521Header = Data([
                0x30, 0x81, 0x9b, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0x03, 0x81, 0x86, 0x00
            ])
            uniformPublicKeyBytes.append(p521Header)
            
        default:
            throw PubKeyFormatError.unsupportedECCurve(size: size)
        }
        
        // Append the raw uncompressed EC points extracted from iOS
        uniformPublicKeyBytes.append(rawPublicKeyData)
        
    } else if keyType == (kSecAttrKeyTypeRSA as String) {
        // We must verify the size to append the correct ASN.1 SPKI header
        guard let size = keySize else {
            throw PubKeyFormatError.unknownKeySize
        }
        
        switch size {
        case 2048:
            let rsa2048Header = Data([
                0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
            ])
            uniformPublicKeyBytes.append(rsa2048Header)
            
        case 3072:
            let rsa3072Header = Data([
                0x30, 0x82, 0x01, 0xa2, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8f, 0x00
            ])
            uniformPublicKeyBytes.append(rsa3072Header)
            
        case 4096:
            let rsa4096Header = Data([
                0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00
            ])
            uniformPublicKeyBytes.append(rsa4096Header)
            
        default:
            // Reject non-standard sizes to prevent memory/parsing corruption
            throw PubKeyFormatError.unsupportedRSASize(size: size)
        }
        
        // Append the raw PKCS#1 bytes extracted from iOS to the selected SPKI header
        uniformPublicKeyBytes.append(rawPublicKeyData)
        
    } else {
        throw PubKeyFormatError.unsupportedKeyType(type: keyType)
    }
    
    // Format
    switch format {
    case .PEM:
        let base64Encoded = uniformPublicKeyBytes.base64EncodedString(options: .lineLength64Characters)
        let formattedPubKey = "-----BEGIN PUBLIC KEY-----\n\(base64Encoded)\n-----END PUBLIC KEY-----"
        return .str(formattedPubKey)
        
    case .B64:
        let formattedPubKey = uniformPublicKeyBytes.base64EncodedString()
        return .str(formattedPubKey)
        
    case .B64URL:
        let formattedPubKey = base64URLEncode(uniformPublicKeyBytes)
        return .str(formattedPubKey)
        
    case .SPKI:
        return .data(uniformPublicKeyBytes)
    }
}
