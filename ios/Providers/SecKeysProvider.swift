import Security

protocol SecKeysProvider {
    func createWithData(
        _ keyData: CFData,
        _ attributes: CFDictionary,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> SecKey?
    
    func createRandomKey(
        _ parameters: CFDictionary,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> SecKey?
    
    func copyPublicKey(_ key: SecKey) -> SecKey?
    
    func copyExternalRepresentation(
        _ key: SecKey,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> CFData?
    
    func verifySignature(
        _ key: SecKey,
        _ algorithm: SecKeyAlgorithm,
        _ signedData: CFData,
        _ signature: CFData,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> Bool
}

struct SecKeys: SecKeysProvider {
    func createWithData(
        _ keyData: CFData,
        _ attributes: CFDictionary,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> SecKey? {
        return SecKeyCreateWithData(keyData, attributes, error)
    }
    
    func createRandomKey(
        _ parameters: CFDictionary,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> SecKey? {
        return SecKeyCreateRandomKey(parameters, error)
    }
    
    func copyPublicKey(_ key: SecKey) -> SecKey? {
        return SecKeyCopyPublicKey(key)
    }
    
    func copyExternalRepresentation(
        _ key: SecKey,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> CFData? {
        return SecKeyCopyExternalRepresentation(key, error)
    }
    
    func verifySignature(
        _ key: SecKey,
        _ algorithm: SecKeyAlgorithm,
        _ signedData: CFData,
        _ signature: CFData,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> Bool {
        return SecKeyVerifySignature(key, algorithm, signedData, signature, error)
    }
}
