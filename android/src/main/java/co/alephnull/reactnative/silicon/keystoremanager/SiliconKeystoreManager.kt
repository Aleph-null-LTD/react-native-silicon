package co.alephnull.reactnative.silicon.keystoremanager

import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import co.alephnull.reactnative.silicon.SiliconResult
import java.security.KeyPairGenerator
import java.util.Base64
import expo.modules.kotlin.AppContext

class SiliconKeystoreManager(private val appContext: AppContext) {

    fun genKey(alias: String, opts: GenerateKeyOptions): SiliconResult<String> {
        // Check if the device supports StrongBox
        val canUseStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                appContext.reactContext?.packageManager?.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE) == true

        var useStrongBox: Boolean
        val requireStrongBox: Boolean

        when (opts.android.hardwarePolicy) {
            HardwarePolicy.REQUIRE_STRONGBOX -> { useStrongBox = true; requireStrongBox = true }
            HardwarePolicy.PREFER_STRONGBOX -> { useStrongBox = true; requireStrongBox = false }
            HardwarePolicy.USE_TEE -> { useStrongBox = false; requireStrongBox = false }
        }

        // Fail-fast if StrongBox was required but not supported
        if (useStrongBox && requireStrongBox && !canUseStrongBox) {
            return SiliconResult.Failure("STRONGBOX_NOT_SUPPORTED", "StrongBox is not supported on this device")
        }

        // If StrongBox was preferred but not required,
        // and the device doesn't support it, disable it
        if (useStrongBox && !canUseStrongBox) {
            useStrongBox = false;
        }

        val alg = when (opts.android.algorithm) {
            KeyAlgorithm.ES256 -> KeyProperties.KEY_ALGORITHM_EC
        }

        // Initialize the Generator
        val kpg = KeyPairGenerator.getInstance(
            alg,
            "AndroidKeyStore"
        )

        // Iterate through purpose array and OR the values together
        val purpose = 0;
        for (p in opts.purposes) {
            when (p) {
                KeyPurpose.SIGN -> purpose or KeyProperties.PURPOSE_SIGN
                KeyPurpose.VERIFY -> purpose or KeyProperties.PURPOSE_VERIFY
                KeyPurpose.ENCRYPT -> purpose or KeyProperties.PURPOSE_ENCRYPT
                KeyPurpose.DECRYPT -> purpose or KeyProperties.PURPOSE_DECRYPT
            }
        }

        @SuppressLint("WrongConstant") // Suppress the lint on setDigests - we know that the values are correct here
        val parameterSpec = KeyGenParameterSpec.Builder(
            alias,
            purpose
        ).run {
            when (opts.android.algorithm) {
                KeyAlgorithm.ES256 -> setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1")) // ES256
            }

            // Map the digests to an array of the relevant constants
            val digests: Array<String> = opts.android.digests.mapNotNull { d ->
                when (d) {
                    KeyDigest.SHA256 -> KeyProperties.DIGEST_SHA256
                    else -> null
                }
            }.toTypedArray()

            setDigests(*digests)

            if (useStrongBox) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                } else {
                    // Should never get here, this is just a failsafe
                    throw Exception("Attempted to use StrongBox on unsupported SDK version (${Build.VERSION.SDK_INT})");
                }
            }

            setUserAuthenticationRequired(opts.userAuth.require)

            if (opts.userAuth.require) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    val authFlags = when (opts.userAuth.policy) {
                        AuthPolicy.BIOMETRICS_ONLY -> KeyProperties.AUTH_BIOMETRIC_STRONG
                        AuthPolicy.BIOMETRICS_OR_CREDENTIAL -> KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                    }

                    setUserAuthenticationParameters(opts.userAuth.timeout, authFlags)

                    if (opts.userAuth.invalidateOnChange) {
                        setInvalidatedByBiometricEnrollment(true)
                    } else {
                        setInvalidatedByBiometricEnrollment(false)
                    }
                } else { // Fallback for older Android devices (API 29 and below)
                    val timeout = if (opts.userAuth.timeout == 0) {
                        -1 // -1 enforces authentication for every use, but OS fallback rules apply
                    } else {
                        opts.userAuth.timeout
                    }

                    @Suppress("DEPRECATION") // Suppress the deprecation - this is a fallback for old devices
                    setUserAuthenticationValidityDurationSeconds(timeout)
                }
            }

            build()
        }

        kpg.initialize(parameterSpec)

        // Generate the Key
        val keyPair = kpg.generateKeyPair()

        // TODO: Possibly use Base64Url
        // We encode to Base64 so it crosses the bridge as a string
        val b64Key = Base64.getEncoder().encodeToString(keyPair.public.encoded)
        return SiliconResult.Success(b64Key);

    }

    fun attestKey(alias: String) {

    }
}