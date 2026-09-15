import LocalAuthentication

/// A contract representing a single, stateful biometric authentication session.
protocol AuthContextProvider {
    var ref: LAContext { get }
    var interactionNotAllowed: Bool { get set }
    var localizedReason: String { get set }
    var evaluatedPolicyDomainState: Data? { get }
    func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool
}

/// A stateful wrapper around Apple's `LAContext`.
///
/// `AuthContext` represents a single authentication lifecycle. Because `LAContext`
/// retains policy evaluation results (such as `evaluatedPolicyDomainState`) in memory,
/// instances of this class **should not be reused** across independent cryptographic operations.
///
/// - Important: Create a fresh instance for each operation via `AuthContextSessionProvider`.
final class AuthContext: AuthContextProvider {
    private let context: LAContext
    
    init() {
        self.context = LAContext()
    }
    
    /// Reference to the underlying LAContext instance
    var ref: LAContext {
        get {
            return context
        }
    }
    
    var interactionNotAllowed: Bool {
        get {
            return context.interactionNotAllowed
        }
        set (isAllowed) {
            context.interactionNotAllowed = isAllowed
        }
    }
    
    var localizedReason: String {
        get {
            return context.localizedReason
        }
        set(newReason) {
            context.localizedReason = newReason
        }
    }
    
    var evaluatedPolicyDomainState: Data? {
        return context.evaluatedPolicyDomainState
    }
    
    func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
        return context.canEvaluatePolicy(policy, error: error)
    }
}

/// A factory contract for spawning isolated authentication context sessions.
protocol AuthContextSessionProvider {
    func start() -> AuthContextProvider
}

/// A stateless dependency-injection provider that generates new `AuthContext` sessions.
///
/// Inject this struct rather than a raw `AuthContextProvider`.
/// This ensures every method invocation gets a clean `LAContext` lifecycle,
/// preventing stale biometric state from leaking between calls.
struct AuthContextSession: AuthContextSessionProvider {
    func start() -> AuthContextProvider {
        return AuthContext()
    }
}
