import ExpoModulesCore

final class SiliconException: Exception {
    private let customCode: String
    private let customMessage: String
    public let underlyingCause: Error?

    public init(code: String, message: String, cause: Error? = nil) {
        self.customCode = code
        self.customMessage = message
        self.underlyingCause = cause
        super.init()
    }

    // Override the default Expo error code (which is normally just the class name)
    override var code: String {
        return customCode
    }

    // Override the default Expo error message
    override var reason: String {
        if let cause = underlyingCause {
            return "\(customMessage) | Cause: \(cause.localizedDescription)"
        }
        return customMessage
    }
}
