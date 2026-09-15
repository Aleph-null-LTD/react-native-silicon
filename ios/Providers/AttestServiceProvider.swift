import DeviceCheck

protocol AttestServiceProvider {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
}

struct AttestService: AttestServiceProvider {
    var isSupported: Bool {
        return DCAppAttestService.shared.isSupported
    }
    
    func generateKey() async throws -> String {
        return try await DCAppAttestService.shared.generateKey()
    }
    
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        return try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash);
    }
}
