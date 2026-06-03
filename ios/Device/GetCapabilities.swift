import Foundation
import LocalAuthentication
import CryptoKit
import DeviceCheck

enum SiliconDevice {
    static func getCapabilities() -> SiliconResult<[String: Any]> {
            let context = LAContext()
            var error: NSError?

            // Secure Enclave
            let securityLevel = SecureEnclave.isAvailable ? "IOS_SECURE_ENCLAVE" : "SOFTWARE"

            // Biometric / Passcode Status
            let canUseBiometrics = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
            let canUseDeviceCredential = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)

            let userAuthLevel: String
            if canUseBiometrics {
                userAuthLevel = "BIOMETRICS_STRONG"
            } else if canUseDeviceCredential {
                userAuthLevel = "DEVICE_CREDENTIAL"
            } else {
                userAuthLevel = "NONE"
            }

            // Check for Key Attestation Support (iOS 14+)
            let canAttest = DCAppAttestService.shared.isSupported

            // Construct the payload dictionary
            let capabilities: [String: Any] = [
                "securityLevel": securityLevel,
                "userAuthLevel": userAuthLevel,
                "canAttest": canAttest
            ]

            return .success(capabilities)
        }
}
