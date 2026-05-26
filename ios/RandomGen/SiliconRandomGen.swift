
enum SiliconRandomGen {
    static func generate(length: Int, format: RandomBytesFormat) -> SiliconResult<Any> {
        // Allocate an empty array of 8-bit unsigned integers (bytes)
        var randomBytes = [UInt8](repeating: 0, count: length)
        
        // Fill the array with secure random bytes
        let status = SecRandomCopyBytes(kSecRandomDefault, length, &randomBytes)
        
        guard status == errSecSuccess else {
            return .failure(
                code: "RANDOM_GEN_FAILED",
                message: "Failed to generate secure random bytes. OSStatus: \(status)",
                nativeStack: nil
            )
        }
        
        // Convert to Foundation Data object for easy string encoding
        let data = Data(randomBytes)
        
        // Format and return
        switch format {
        case .B64:
            let formatted = data.base64EncodedString() // Native NO_WRAP equivalent
            return .success(formatted)
            
        case .B64URL:
            // Swift quirk: iOS does not have a native URL-safe Base64 flag.
            // We must perform the standard RFC 4648 character replacements manually.
            let formatted = data.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .trimmingCharacters(in: CharacterSet(charactersIn: "="))
            
            return .success(formatted)
            
        case .BYTES:
            // Return the raw [UInt8] array (or Data, depending on your Expo bridge preference)
            return .success(randomBytes)
        }
    }
}
