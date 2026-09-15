import Testing

extension SiliconResult {
    var isSuccess: Bool {
        if case .success = self { return true }
        return false
    }
    
    var isFailure: Bool {
        if case .failure = self { return true }
        return false
    }
    
    func unwrap() throws -> String {
        guard case .success(let value) = self else {
            throw TestError("Expected success but got failure: \(self)")
        }
        return value
    }
    
    func unwrapError() throws -> SiliconError {
        guard case .failure(let error) = self else {
            throw TestError("Expected failure but got success")
        }
        return error
    }
}

struct TestError: Error {
    let message: String
    init(_ message: String) { self.message = message }
}
