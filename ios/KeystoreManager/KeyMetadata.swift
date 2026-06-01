
struct KeyMetadata {
    // Caching layer for faster retrieval
    private static var cache: [String: [String: Any]] = [:]
    
    static func store(alias: String, opts: GenerateKeyOptions, isHardwareBacked: Bool) -> Bool {
        let metadata: [String: Any] = [
            "purposes": opts.purposes,
            "isHardwareBacked": isHardwareBacked
        ]
        
        // Store the metadata as JSON in the keychain
        if let jsonData = try? JSONSerialization.data(withJSONObject: metadata),
            let jsonString = String(data: jsonData, encoding: .utf8) {
            
            let isPurposeSuccess = KeychainHelper.save(key: "\(alias)_metadata", value: jsonString)
            if !isPurposeSuccess {
                return false
            }
            
            // Store it in the cache
            cache[alias] = metadata
        }
        
        return true
    }
    
    static func delete(alias: String) -> Bool {
        // If it has been cached, delete it
        if let i = cache.index(forKey: alias) {
            cache.remove(at: i)
        }
        
        // Delete it from the keychain
        let isDeleted = KeychainHelper.delete(key: "\(alias)_metadata")
        return isDeleted
    }
    
    static func get(alias: String) -> [String: Any]? {
        // If cached, return it straight away
        if let cached = cache[alias] {
            return cached
        }
        
        // If not cached, read it from keychain and parse the JSON
        if let jsonString = KeychainHelper.read(key: "\(alias)_metadata"),
           let jsonData = jsonString.data(using: .utf8),
           let parsed = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] {
            
            // Store it in the cache
            cache[alias] = parsed
            return parsed
        }
        
        return nil
    }
}
