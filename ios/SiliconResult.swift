enum SiliconResult<T> {
    case success(T)
    case failure(code: String, message: String, nativeStack: String?)
    
    // Convert to dictionary for the React Native bridge
    func toBridgeMap() -> [String: Any] {
        switch self {
        case .success(let data):
            return ["success": true, "data": data]
        case .failure(let code, let message, let nativeStack):
            var dict: [String: Any] = [
                "success": false,
                "errorCode": code,
                "errorMessage": message
            ]
            if let stack = nativeStack { dict["nativeStack"] = stack }
            return dict
        }
    }
}
