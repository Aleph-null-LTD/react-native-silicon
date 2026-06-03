enum KeyMetaDataStoreError: Error {
    case jsonEncoding(message: String)
    case failedSave(message: String)
}

enum KeyMetaDataReadError: Error {
    case jsonDecoding(message: String)
    case failedRead(message: String)
}

struct KeyMetadata: Codable {
    let purposes: [KeyPurpose]
    let digests: [KeyDigests]?
    let signaturePaddingAlgorithm: SignaturePaddingAlgorithm?
    let isHardwareBacked: Bool
    let userAuthRequire: Bool
    let userAuthTimeout: Int
    let userAuthInvalidateOnEnrollment: Bool
    let userAuthPolicy: AuthPolicy
}

struct KeyMetadataStore {
    // Caching layer for faster retrieval
    private static var cache: [String: KeyMetadata] = [:]
    
    // Mutex used for protecting the cache from race conditions
    private static let mutex = NSLock()
    
    static func store(alias: String, opts: GenerateKeyOptions, isHardwareBacked: Bool) throws -> Void {
        mutex.lock()
        defer { mutex.unlock() }
        
        let metadata = KeyMetadata(
            purposes: opts.purposes,
            digests: opts.ios.digests,
            signaturePaddingAlgorithm: opts.ios.signaturePaddingAlgorithm,
            isHardwareBacked: isHardwareBacked,
            userAuthRequire: opts.userAuth.require,
            userAuthTimeout: opts.userAuth.timeout,
            userAuthInvalidateOnEnrollment: opts.userAuth.invalidateOnEnrollment,
            userAuthPolicy: opts.userAuth.policy
        )
        
        do {
            let jsonData = try JSONEncoder().encode(metadata)
            
            // Store the metadata as JSON in the keychain
            let isSaveSuccessful = KeychainHelper.saveData(key: "\(alias)_metadata", data: jsonData)
            if !isSaveSuccessful {
                throw KeyMetaDataStoreError.failedSave(message: "Failed to save key metadata to keychain")
            }
            
            // Store it in the cache
            cache[alias] = metadata
            
        } catch {
            throw KeyMetaDataStoreError.jsonEncoding(message: "Failed to encode key metadata as JSON: \(error.localizedDescription)")
        }
    }
    
    static func delete(alias: String) -> Bool {
        mutex.lock()
        defer { mutex.unlock() }
        
        // If it has been cached, delete it
        cache[alias] = nil
        
        // Delete it from the keychain
        let isDeleted = KeychainHelper.delete(key: "\(alias)_metadata")
        return isDeleted
    }
    
    static func get(alias: String) throws -> KeyMetadata {
        mutex.lock()
        defer { mutex.unlock() }
        
        // If cached, return it straight away
        if let cached = cache[alias] {
            return cached
        }
        
        // If not cached, read it from keychain and parse the JSON
        guard let jsonData = KeychainHelper.readData(key: "\(alias)_metadata") else {
            throw KeyMetaDataReadError.failedRead(message: "Failed to read key metadata from keychain.")
        }
        
        do {
            let parsed = try JSONDecoder().decode(KeyMetadata.self, from: jsonData)
            
            // Store it in the cache
            cache[alias] = parsed
            return parsed
        } catch {
            throw KeyMetaDataReadError.jsonDecoding(message: "Failed to decode key metadata JSON: \(error.localizedDescription)")
        }
            
    }
}
