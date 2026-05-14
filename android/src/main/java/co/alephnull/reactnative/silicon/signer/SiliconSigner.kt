package co.alephnull.reactnative.silicon.signer

import co.alephnull.reactnative.silicon.SiliconResult
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import co.alephnull.reactnative.silicon.PayloadByteArr
import co.alephnull.reactnative.silicon.PayloadText
import co.alephnull.reactnative.silicon.PayloadType
import co.alephnull.reactnative.silicon.SiliconException
import expo.modules.kotlin.AppContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

class SiliconSigner(private val appContext: AppContext, private val keystore: KeyStore) {

    suspend fun sign(alias: String, payload: PayloadType, opts: SignOptions): SiliconResult<String> {
        // Grab the active UI context and cast it safely
        val activity = appContext.currentActivity as? FragmentActivity
            ?: return SiliconResult.Failure(
                "NO_ACTIVITY",
                "Current activity is null or not a FragmentActivity."
            )

        val payloadBytes = when (payload) {
            // Convert the string payload to raw UTF-8 bytes
            is PayloadText -> payload.text.toByteArray(Charsets.UTF_8)

            // Use the raw bytes
            is PayloadByteArr -> payload.arr
        }

        try {
            // Verify that the key exists
            if (!keystore.containsAlias(alias)) {
                return SiliconResult.Failure("KEY_NOT_FOUND", "No key found for alias: $alias")
            }

            // Grab the PrivateKey reference from the hardware provider
            // The password parameter is always null for AndroidKeyStore
            val privateKey = keystore.getKey(alias, null) as? PrivateKey
                ?: return SiliconResult.Failure("INVALID_KEY", "Key is not a valid PrivateKey")

            val algorithmResult = getSignatureAlgorithm(privateKey, opts.algorithm)
            if (algorithmResult !is SiliconResult.Success) return algorithmResult
            val alg = algorithmResult.data;

            // Initialize the Signature Engine for ES256
            val signatureEngine = Signature.getInstance(alg).apply {
                initSign(privateKey)
            }

            // Pass the bytes into the Engine
            signatureEngine.update(payloadBytes)

            // Execute the hardware signature
            val signatureBytes = signatureEngine.sign()

            // Encode the raw signature bytes
            val base64Signature = encodeSignature(signatureBytes, opts.encoding)

            return SiliconResult.Success(base64Signature)

        } catch (e: UserNotAuthenticatedException) {
            // The hardware requires user authentication.

            // We must recreate the engine reference to pass into a fresh CryptoObject session
            val privateKey = keystore.getKey(alias, null) as PrivateKey

            val algorithmResult = getSignatureAlgorithm(privateKey, opts.algorithm)
            if (algorithmResult !is SiliconResult.Success) return algorithmResult
            val alg = algorithmResult.data;

            val freshSignatureEngine = Signature.getInstance(alg).apply {
                initSign(privateKey)
            }

            // Delegate to the suspended UI Coroutine
            return promptAndSign(freshSignatureEngine, payloadBytes, opts, activity)

        } catch (e: KeyPermanentlyInvalidatedException) {
            // Occurs if the user enrolled new biometrics and invalidateOnNewBiometrics was true
            return SiliconResult.Failure(
                "KEY_INVALIDATED",
                "Key was permanently invalidated because biometric enrollment changed"
            )

        } catch (e: SiliconException) {
            throw e

        } catch (e: Exception) {
            return SiliconResult.Failure("SIGNING_FAILED", e.localizedMessage ?: "Unknown signing error", e.stackTraceToString())
        }
    }

    private suspend fun promptAndSign(
        signatureEngine: Signature,
        payloadBytes: ByteArray,
        opts: SignOptions,
        activity: FragmentActivity
    ): SiliconResult<String> = withContext(Dispatchers.Main) {
        suspendCancellableCoroutine { continuation ->
            val executor = ContextCompat.getMainExecutor(activity)

            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    try {
                        // Grab the unlocked engine from the OS result
                        val unlockedSignature = result.cryptoObject?.signature
                            ?: throw IllegalStateException("CryptoObject signature missing.")

                        // Sign the payload
                        unlockedSignature.update(payloadBytes)
                        val signatureBytes = unlockedSignature.sign()

                        val base64Signature = encodeSignature(signatureBytes, opts.encoding)

                        // Resume the JS Promise with Success
                        continuation.resume(
                            SiliconResult.Success(base64Signature)
                        )

                    } catch (e: Exception) {
                        continuation.resume(
                            SiliconResult.Failure("PROMPT_SIGN_FAILED", e.message ?: "Failed post-auth", e.stackTraceToString()),
                        )
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    // Handles user cancellations, lockouts, or missing hardware
                    continuation.resume(SiliconResult.Failure("AUTH_ERROR_$errorCode", errString.toString()))
                }

                override fun onAuthenticationFailed() {
                    // Triggered on a bad biometric scan. The OS automatically keeps the UI open to retry
                    // so we do NOT resume/cancel the coroutine here
                }
            }

            val biometricPrompt = BiometricPrompt(activity, executor, callback)
            val cryptoObject = BiometricPrompt.CryptoObject(signatureEngine)

            // Configure the text rendered on the native OS dialog overlay
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authenticate to continue")
                .setSubtitle("Hardware Key Security")
                // Standard fallback setup: Require a cancel button if we are strictly using biometrics.
                // If supporting PIN fallback on modern API levels, omit this and use setAllowedAuthenticators instead.
                .setNegativeButtonText("Cancel")
                .build()

            // Handle clean cancellation if the JS side cancels the promise early
            continuation.invokeOnCancellation {
                biometricPrompt.cancelAuthentication()
            }

            // Launch the native overlay linked to the crypto session
            biometricPrompt.authenticate(promptInfo, cryptoObject)
        }
    }

    // Gets the algorithm string to use for signing
    private fun getSignatureAlgorithm(key: PrivateKey, algorithm: SignAlgorithm): SiliconResult<String> {
        return when (key.algorithm) {
            "EC" -> when (algorithm) {
                SignAlgorithm.SHA256 -> SiliconResult.Success("SHA256withECDSA")
            }

            "RSA" -> when (algorithm) {
                SignAlgorithm.SHA256 -> SiliconResult.Success("SHA256withRSA")
            }

            else -> SiliconResult.Failure("UNSUPPORTED_KEY_FAMILY", "Unsupported key family: ${key.algorithm}")
        }
    }

    // Encodes the signature with the specified encoding type
    private fun encodeSignature(bytes: ByteArray, encoding: SignEncoding): String {
        return when (encoding) {
            // Base64Url - use URL-safe chars, disable padding and the android default wrap
            SignEncoding.B64_URL -> Base64.encodeToString(
                bytes,
                Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
            )

            // Base64 - disable the android default wrap
            SignEncoding.B64 -> Base64.encodeToString(bytes, Base64.NO_WRAP)
        }
    }
}