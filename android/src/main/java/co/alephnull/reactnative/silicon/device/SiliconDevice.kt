package co.alephnull.reactnative.silicon.device

import android.content.pm.PackageManager
import android.os.Build
import androidx.biometric.BiometricManager
import co.alephnull.reactnative.silicon.SiliconResult
import expo.modules.kotlin.AppContext


class SiliconDevice(private val appContext: AppContext) {

    fun getCapabilities(): SiliconResult<Map<String, Any?>> {
        try {
            val packageManager = appContext.reactContext?.packageManager
            val biometricManager = BiometricManager.from(appContext.reactContext!!)

            // Check for StrongBox
            val hasStrongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageManager?.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE) ?: false
            } else {
                false
            }

            // Check for TEE (Trusted Execution Environment / Hardware isolation)
            // Almost all devices since Android 6.0 have this, but we verify it via the feature flag
            val hasHardwareKeystore = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                packageManager?.hasSystemFeature(PackageManager.FEATURE_HARDWARE_KEYSTORE) ?: true
            } else {
                // Fallback for older but still compatible versions
                true
            }

            val securityLevel = if (hasStrongBox) {
                "ANDROID_STRONGBOX"
            } else if (hasHardwareKeystore) {
                "ANDROID_TEE"
            } else {
                "SOFTWARE"
            }

            // Check Biometric status
            val canUseStrong =
                biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
            val canUseWeak =
                biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK) == BiometricManager.BIOMETRIC_SUCCESS
            val canUseDeviceCredential =
                biometricManager.canAuthenticate(BiometricManager.Authenticators.DEVICE_CREDENTIAL) == BiometricManager.BIOMETRIC_SUCCESS

            val userAuthLevel = if (canUseStrong) {
                "BIOMETRICS_STRONG"
            } else if (canUseWeak) {
                "BIOMETRICS_WEAK"
            } else if (canUseDeviceCredential) {
                "DEVICE_CREDENTIAL"
            } else {
                "NONE"
            }

            // Return as a Map (which becomes a JS Object)
            return SiliconResult.Success(
                mapOf(
                    "securityLevel" to securityLevel,
                    "userAuthLevel" to userAuthLevel,
                    "canAttest" to (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
                )
            )
        } catch (e: Exception) {
            return SiliconResult.Failure(
                "GET_CAPABILITIES_FAILED",
                e.localizedMessage ?: "Failed to get capabilities",
                e.stackTraceToString()
            )
        }
    }
}