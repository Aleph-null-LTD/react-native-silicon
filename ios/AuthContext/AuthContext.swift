import LocalAuthentication
import Foundation

struct AuthContext {
    private static var biometricContext: LAContext?
    private static var biometricAuthTime: Date = .distantPast
    
    private static var passcodeContext: LAContext?
    private static var passcodeAuthTime: Date = .distantPast
    
    private static let mutex = NSLock()
    
    static func get(forTimeout timeoutSecs: Double, allowsPasscode: Bool) -> LAContext {
        // Lock the mutex to prevent race conditions
        mutex.lock()
        defer { mutex.unlock() }
        
        if (allowsPasscode) {
            return handleContext(context: &passcodeContext, authTime: &passcodeAuthTime, timeoutSecs: timeoutSecs)
        } else {
            return handleContext(context: &biometricContext, authTime: &biometricAuthTime, timeoutSecs: timeoutSecs)
        }
    }
    
    private static func handleContext(context: inout LAContext?, authTime: inout Date, timeoutSecs: Double) -> LAContext {
        let now = Date()
        
        if let ctx = context {
            let timeElapsed = now.timeIntervalSince(authTime)
        
            // If still within the timeout window, return the current context
            // a timeout of 0 will always create a new context
            if timeoutSecs > 0 && timeElapsed <= timeoutSecs {
                return ctx
            }
        }
        
        // NOTE: To prevent race conditions, we do not invalidate the old context
        // old context will be cleaned up by ARC once no references to it are held
        
        // Create a fresh unauthenticated context
        let newContext = LAContext()
        newContext.localizedReason = "Authenticate to continue"
        
        context = newContext
        authTime = now
        
        return newContext
    }
}
