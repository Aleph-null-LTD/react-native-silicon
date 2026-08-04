enum KeychainHelperError: Error {
    case saveFailed(message: String)
    case readFailed(message: String)
    case deleteFailed(message: String)
    case listAllFailed(message: String)
    case existsFailed(message: String)
    
    var errorDescription: String {
        switch self {
        case .saveFailed(let message): return message
        case .readFailed(let message): return message
        case .deleteFailed(let message): return message
        case .listAllFailed(let message): return message
        case .existsFailed(let message): return message
        }
    }
}

protocol KeychainHelping {
    func saveStr(key: String, value: String) throws -> Void
    func saveData(key: String, data: Data) throws -> Void
    func readStr(key: String) throws -> String?
    func readData(key: String) throws -> Data?
    func delete(key: String) throws -> Bool
    func exists(key: String) throws -> Bool
    func listAll() throws -> [String]?
}

// TODO: Use the injected secItems rather than raw functions
struct KeychainHelper: KeychainHelping {
    //  -- Dependencies --
    private let secItems: SecItemsProvider
    
    // -- State --
    // All internal data is stored with this service
    private let service = "co.alephnull.reactnative.silicon"
    private let prefix: String
    
    // -- Init --
    init(secItems: SecItemsProvider) {
        self.secItems = secItems
        prefix = "\(service)."
    }
    
    // -- Methods --
    func saveStr(key: String, value: String) throws -> Void {
        let data = value.data(using: .utf8)!
        try saveData(key: key, data: data)
    }
    
    func saveData(key: String, data: Data) throws -> Void {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "\(prefix)\(key)",
            kSecAttrService as String: service,
            kSecValueData as String: data
        ]
        
        // Delete any existing item to avoid duplicate key errors
        // We know at this point, if the data exists, it is orphaned and safe to delete
        _ = secItems.delete(query as CFDictionary)
        
        let status = secItems.add(query as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            throw KeychainHelperError.saveFailed(message: "Failed to save key '\(key)' in keychain. OSStatus: \(status)")
        }
    }
    
    func readStr(key: String) throws -> String? {
        guard let data = try readData(key: key) else {
            return nil
        }
        
        return String(data: data, encoding: .utf8)
    }
    
    func readData(key: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "\(prefix)\(key)",
            kSecAttrService as String: service,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var dataTypeRef: AnyObject?
        let status = secItems.copyMatching(query as CFDictionary, &dataTypeRef)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainHelperError.readFailed(message: "Failed to read data from key '\(key)' on keychain. OSStatus: \(status)")
        }
        
        if status == errSecItemNotFound {
            return nil
        }
        
        guard let data = dataTypeRef as? Data else {
            throw KeychainHelperError.readFailed(message: "Failed to read data from key '\(key)' on keychain: Received unexpected data type from the OS.")
        }
        
        return data
    }
    
    func delete(key: String) throws -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "\(prefix)\(key)",
            kSecAttrService as String: service,
        ]
        
        let status = secItems.delete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainHelperError.deleteFailed(message: "Failed to delete key '\(key)' from keychain. OSStatus: \(status)")
        }
        
        return status == errSecSuccess
    }
    
    func exists(key: String) throws -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "\(prefix)\(key)",
            kSecAttrService as String: service,
            kSecReturnAttributes as String: false,
            kSecReturnData as String: false,
            // Do not prompt for biometrics if the item is protected by Face ID
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
        ]
        
        // Pass 'nil' for the result. We only care about the status code.
        let status = secItems.copyMatching(query as CFDictionary, nil)
        
        switch status {
        case errSecSuccess:
            // It exists and is fully accessible.
            return true
            
        case errSecInteractionNotAllowed, errSecAuthFailed:
            // It exists, but the device is currently locked
            // or we intentionally skipped the Face ID prompt.
            return true
            
        case errSecItemNotFound:
            // It definitively does not exist.
            return false
            
        default:
            throw KeychainHelperError.existsFailed(message: "KeychainHelper.exists failed. OSStatus: \(status)")
        }
    }
    
    // Lists all our internal keys that are stored in keychain (our internal prefix will be trimmed)
    func listAll() throws -> [String]? {
        var keyList: [String] = []
        
        let passQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitAll,
            //kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
        ]
        
        var passResult: AnyObject?
        let passStatus = secItems.copyMatching(passQuery as CFDictionary, &passResult)
        
        if passStatus == errSecSuccess, let passItems = passResult as? [[String: Any]] {
            for item in passItems {
                if let accountStr = item[kSecAttrAccount as String] as? String {
                    if accountStr.hasPrefix(prefix) {
                        let trimmedKey = String(accountStr.dropFirst(prefix.count))
                        keyList.append(trimmedKey)
                    }
                }
            }
        } else if passStatus != errSecItemNotFound {
            throw KeychainHelperError.listAllFailed(message: "Failed to list internal keychain. OSStatus: \(passStatus)")
        }
        
        if keyList.count > 0 {
            return keyList
        } else {
            return nil
        }
    }
}
