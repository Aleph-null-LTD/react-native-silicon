enum GetPubKeyDataError: Error {
    case invalidAlias(message: String)
    case keyNotFound(message: String)
    case unsupportedKeyFamily(message: String)
    case failed(message: String)
    
    var errorDescription: String? {
        switch self {
        case .invalidAlias(let message):
            return message
        case .keyNotFound(let message):
            return message
        case .unsupportedKeyFamily(let message):
            return message
        case .failed(let message):
            return message
        }
    }
}

func getPubKeyData(alias: String) throws -> (rawData: Data, dict: [String: Any]) {
    guard let tag = alias.data(using: .utf8) else {
        throw GetPubKeyDataError.invalidAlias(message: "Failed to encode alias to data.")
    }
    
    // Query the Keychain for ANY key matching this alias
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecReturnRef as String: true,
        kSecReturnAttributes as String: true, // Gets Metadata dict for the key
        kSecMatchLimit as String: kSecMatchLimitOne
    ]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    
    if status == errSecItemNotFound {
        throw GetPubKeyDataError.keyNotFound(message: "No key exists for alias: '\(alias)'")
    }
    
    guard status == errSecSuccess else {
        throw GetPubKeyDataError.failed(message: "Keychain lookup failed with OSStatus: \(status)")
    }
    
    guard let dict = item as? [String: Any],
          let rawRef = dict[kSecValueRef as String] else {
        throw GetPubKeyDataError.failed(message: "Failed to cast Keychain item to SecKey.")
    }
    
    // Exact match for Kotlin's symmetric key rejection
    let keyClass = dict[kSecAttrKeyClass as String] as? String
    if keyClass == (kSecAttrKeyClassSymmetric as String) {
        throw GetPubKeyDataError.unsupportedKeyFamily(message: "The key stored under alias '\(alias)' is a symmetric key. Public key extraction is only supported for asymmetric keypairs (RSA/EC).")
    }
    
    // Swift cannot dynamically type-check C-pointers, but the Keychain API
    // guarantees this is a SecKey because we explicitly queried for kSecClassKey
    let keyRef = rawRef as! SecKey
    
    // Extract the Public Key from the reference
    let publicKey: SecKey
    if keyClass == (kSecAttrKeyClassPublic as String) {
        publicKey = keyRef
    } else {
        // If the keychain handed us the Private Key, mathematically extract the Public half
        guard let extractedPub = SecKeyCopyPublicKey(keyRef) else {
            throw GetPubKeyDataError.failed(message: "Failed to extract public key from the private key pair.")
        }
        publicKey = extractedPub
    }
    
    // Export raw PubKey
    var exportError: Unmanaged<CFError>?
    guard let rawPubKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
        let err = exportError?.takeRetainedValue()
        throw GetPubKeyDataError.failed(message: err?.localizedDescription ?? "Failed to export public key bytes.")
    }
    
    return (rawData: rawPubKeyData, dict: dict)
}
