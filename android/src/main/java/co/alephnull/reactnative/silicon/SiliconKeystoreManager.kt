package co.alephnull.reactnative.silicon

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.util.Base64
import expo.modules.kotlin.AppContext

class SiliconKeystoreManager(private val appContext: AppContext) {

    fun genKey(opts: GenerateKeyOptions): SiliconResult<String> {
        val canUseStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                appContext.reactContext?.packageManager?.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYMASTER) == true

        var attemptStrongBox = opts.useStrongBox;

        // Fail-fast is StrongBox was required but not supported
        if (opts.useStrongBox && opts.requireStrongBox && !canUseStrongBox) {
            return SiliconResult.Failure()
        }

        // If StrongBox was preferred but not required,
        // and the device doesn't support it, disable it
        if (opts.useStrongBox && !canUseStrongBox) {
            attemptStrongBox = false;
        }

        try {
            // Initialize the Generator
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )

            // Build the "Blueprint"
            val parameterSpec = KeyGenParameterSpec.Builder(
                opts.alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).run {
                setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1")) // ES256

                setDigests(KeyProperties.DIGEST_SHA256)

                // Hardware Security Settings
                if (attemptStrongBox) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setIsStrongBoxBacked(true)
                    } else {
                        // Should never get here, this is just a failsafe
                        throw Exception("Attempted to use StrongBox on unsupported SDK version (${Build.VERSION.SDK_INT})");
                    }
                }

                // Biometric Requirement
                setUserAuthenticationRequired(opts.requireUserAuth)

                // Invalidate key if new fingerprints are added (Highly secure)
                if (opts.requireUserAuth && opts.invalidateUserAuthOnChange) {
                    setInvalidatedByBiometricEnrollment(true)
                }

                build()
            }

            kpg.initialize(parameterSpec)

            // Generate the Key (Inside the hardware)
            val keyPair = kpg.generateKeyPair()

            // TODO: Possibly use Base64Url
            // Return the Public Key so JS can build the JWK
            // We encode to Base64 so it crosses the bridge as a string
            //return@AsyncFunction Base64.getEncoder().encodeToString(keyPair.public.encoded)
            val b64Key = Base64.getEncoder().encodeToString(keyPair.public.encoded)
            return SiliconResult.Success(b64Key);

        } catch (e: StrongBoxUnavailableException) {
            // Fallback: If user asked for StrongBox but the hardware doesn't have it,
            // should probably throw a custom error or retry with TEE.
            //throw Exception("STRONGBOX_NOT_AVAILABLE")
            return SiliconResult.Failure("STRONGBOX_UNAVAILABLE", e.message)

        } catch (e: Exception) {
            throw Exception("KEY_GENERATION_FAILED: ${e.message}")
        }
    }

    fun attestKey(alias: String) {

    }
}