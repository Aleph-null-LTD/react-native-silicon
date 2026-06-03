
enum SiliconErrorCode: String {
    case INTERNAL_ERROR = "INTERNAL_ERROR"
    case INVALID_ARGUMENT = "INVALID_ARGUMENT"
    case UNSUPPORTED = "UNSUPPORTED"
    case GENERATE_KEY_FAILED = "GENERATE_KEY_FAILED"
    case ATTEST_NOT_SUPPORTED = "ATTEST_NOT_SUPPORTED"
    case ALIAS_IN_USE = "ALIAS_IN_USE"
    case HARDWARE_NOT_AVAILABLE = "HARDWARE_NOT_AVAILABLE"
    case DELETE_FAILED = "DELETE_FAILED"
    case DELETE_ALL_FAILED = "DELETE_ALL_FAILED"
    case KEY_EXISTS_FAILED = "KEY_EXISTS_FAILED"
    case LIST_KEYS_FAILED = "LIST_KEYS_FAILED"
    case GET_PUB_KEY_FAILED = "GET_PUB_KEY_FAILED"
    case KEY_NOT_FOUND = "KEY_NOT_FOUND"
    case VALIDATE_KEY_FAILED = "VALIDATE_KEY_FAILED"
    case ATTEST_KEY_FAILED = "ATTEST_KEY_FAILED"
    case GET_KEY_INFO_FAILED = "GET_KEY_INFO_FAILED"
    case GET_JWK_FAILED = "GET_JWK_FAILED"
    case VERIFY_FAILED = "VERIFY_FAILED"
    //case MALFORMED_SIGNATURE = "MALFORMED_SIGNATURE"
    case KEY_POLICY_VIOLATION = "KEY_POLICY_VIOLATION"
    case INCOMPATIBLE = "INCOMPATIBLE"
    case OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"
    case MALFORMED_DATA = "MALFORMED_DATA"
    case RANDOM_GEN_FAILED = "RANDOM_GEN_FAILED"
    case SIGN_FAILED = "SIGN_FAILED"
    case AUTH_CANCELED = "AUTH_CANCELED"
}

enum SiliconResult<T> {
    case success(T)
    case failure(code: SiliconErrorCode, message: String, nativeStack: String?)
    
    // Convert to dictionary for the React Native bridge
    func toBridgeMap() -> [String: Any] {
        switch self {
        case .success(let data):
            return ["success": true, "data": data]
        case .failure(let code, let message, let nativeStack):
            var dict: [String: Any] = [
                "success": false,
                "errorCode": code.rawValue,
                "errorMessage": "[RN-Silicon: iOS] \(message)"
            ]
            if let stack = nativeStack { dict["nativeStack"] = stack }
            return dict
        }
    }
}
