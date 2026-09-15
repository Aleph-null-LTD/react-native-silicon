
enum SiliconErrorCode: String {
    case INTERNAL_ERROR = "INTERNAL_ERROR"
    case INVALID_ARGUMENT = "INVALID_ARGUMENT"
    case UNSUPPORTED = "UNSUPPORTED"
    case KEY_NOT_FOUND = "KEY_NOT_FOUND"
    case KEY_POLICY_VIOLATION = "KEY_POLICY_VIOLATION"
    case INCOMPATIBLE = "INCOMPATIBLE"
    case OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED"
    case MALFORMED_DATA = "MALFORMED_DATA"
    case AUTH_CANCELED = "AUTH_CANCELED"
    case AUTH_LOCKED_OUT = "AUTH_LOCKED_OUT"
    case BIOMETRICS_NOT_ENROLLED = "BIOMETRICS_NOT_ENROLLED"
    case BIOMETRICS_NOT_AVAILABLE = "BIOMETRICS_NOT_AVAILABLE"
    case AUTH_FAILED = "AUTH_FAILED"
    case KEY_INVALIDATED = "KEY_INVALIDATED"
    case DEVICE_NOT_SECURE = "DEVICE_NOT_SECURE"
    
    // Generate key errors
    case GENERATE_KEY_FAILED = "GENERATE_KEY_FAILED"
    case ATTEST_NOT_AVAILABLE = "ATTEST_NOT_AVAILABLE"
    case ALIAS_IN_USE = "ALIAS_IN_USE"
    case HARDWARE_NOT_AVAILABLE = "HARDWARE_NOT_AVAILABLE"
    
    case DELETE_FAILED = "DELETE_FAILED"
    case DELETE_ALL_FAILED = "DELETE_ALL_FAILED"
    case KEY_EXISTS_FAILED = "KEY_EXISTS_FAILED"
    case LIST_KEYS_FAILED = "LIST_KEYS_FAILED"
    case GET_PUB_KEY_FAILED = "GET_PUB_KEY_FAILED"
    case VALIDATE_KEY_FAILED = "VALIDATE_KEY_FAILED"
    case ATTEST_KEY_FAILED = "ATTEST_KEY_FAILED"
    case GET_KEY_INFO_FAILED = "GET_KEY_INFO_FAILED"
    case GET_JWK_FAILED = "GET_JWK_FAILED"
    case VERIFY_FAILED = "VERIFY_FAILED"
    case RANDOM_GEN_FAILED = "RANDOM_GEN_FAILED"
    case SIGN_FAILED = "SIGN_FAILED"
    //case MALFORMED_SIGNATURE = "MALFORMED_SIGNATURE"
}

protocol ExpressibleAsNil {
    var isNil: Bool { get }
}
extension Optional: ExpressibleAsNil {
    var isNil: Bool { return self == nil }
}

enum SiliconResult<T> {
    case success(T)
    case failure(code: SiliconErrorCode, message: String, nativeStack: String?)
    
    // Convert to dictionary for the React Native bridge
    func toBridgeMap() -> [String: Any] {
        switch self {
        case .success(let data):
            // If the type is Void, omit the data key
            if data is Void {
                return ["success": true]
            }
            
            // If the type is an Optional (e.g. String?), and it's nil, omit the data key
            if let optionalData = data as? ExpressibleAsNil, optionalData.isNil {
                return ["success": true]
            }
            
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

