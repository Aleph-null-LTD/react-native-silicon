import LocalAuthentication
import Foundation

final class AuthContextCache {
    private var authContextSession: AuthContextSessionProvider
    
    private var biometricContext: AuthContextProvider?
    private var biometricAuthTime: Date = .distantPast
    
    private var passcodeContext: AuthContextProvider?
    private var passcodeAuthTime: Date = .distantPast
    
    private let mutex = NSLock()
    
    init(authContextSession: AuthContextSessionProvider) {
        self.authContextSession = authContextSession
    }
    
    func get(forTimeout timeoutSecs: Double, allowsPasscode: Bool) -> AuthContextProvider {
        // Lock the mutex to prevent race conditions
        mutex.lock()
        defer { mutex.unlock() }
        
        if (allowsPasscode) {
            return handleContext(context: &passcodeContext, authTime: &passcodeAuthTime, timeoutSecs: timeoutSecs)
        } else {
            return handleContext(context: &biometricContext, authTime: &biometricAuthTime, timeoutSecs: timeoutSecs)
        }
    }
    
    private func handleContext(context: inout AuthContextProvider?, authTime: inout Date, timeoutSecs: Double) -> AuthContextProvider {
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
        var newContext = authContextSession.start()
        newContext.localizedReason = "Authenticate to continue"
        
        context = newContext
        authTime = now
        
        return newContext
    }
}
