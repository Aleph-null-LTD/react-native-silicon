package co.alephnull.reactnative.silicon.signer

import android.os.Build
import android.security.keystore.KeyInfo
import co.alephnull.reactnative.silicon.SiliconResult
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import co.alephnull.reactnative.silicon.PayloadByteArr
import co.alephnull.reactnative.silicon.PayloadText
import co.alephnull.reactnative.silicon.PayloadType
import co.alephnull.reactnative.silicon.SiliconException
import co.alephnull.reactnative.silicon.helpers.SiliconHelpers
import co.alephnull.reactnative.silicon.onFailure
import expo.modules.kotlin.AppContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.security.InvalidKeyException
import java.security.KeyFactory
import kotlin.coroutines.resume
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.Signature

class SiliconSigner(private val appContext: AppContext, private val keystore: KeyStore, private val helpers: SiliconHelpers) {

    suspend fun sign(alias: String, payload: PayloadType, opts: SignOptions): SiliconResult<String> {
        try {
            // Verify that the key exists
            if (!keystore.containsAlias(alias)) {
                return SiliconResult.Failure("KEY_NOT_FOUND", "No key found for alias: $alias")
            }

            val payloadBytes = when (payload) {
                // Convert the string payload to raw UTF-8 bytes
                is PayloadText -> payload.text.toByteArray(Charsets.UTF_8)

                // Use the raw bytes
                is PayloadByteArr -> payload.arr
            }

            // Grab the PrivateKey reference from the hardware provider
            // The password parameter is always null for AndroidKeyStore
            val privateKey = keystore.getKey(alias, null) as? PrivateKey
                ?: return SiliconResult.Failure("INVALID_KEY", "Key is not a valid PrivateKey")

            val (keyAlgorithm, crv) = helpers.getKeyAlgorithm(privateKey)

            // Set the default digest based on the key algorithm if it is not set
            if (opts.digest == null) {
                opts.digest = when {
                    keyAlgorithm == "ES256" || keyAlgorithm == "RS256" -> SignDigest.SHA256
                    // keyAlgorithm == "ES384" || keyAlgorithm == "RS384" -> SignDigest.SHA384
                    // keyAlgorithm == "ES512" || keyAlgorithm == "RS512" -> SignDigest.SHA512
                    else -> return SiliconResult.Failure(
                        "UNSUPPORTED_KEY_FAMILY",
                        "Key algorithm $keyAlgorithm is not supported for this function"
                    )
                }
            }

            var signatureBytes: ByteArray

            // Inspect the key and trigger the user auth flow if auth is required for every use
            val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)

            if (keyInfo.isUserAuthenticationRequired &&
                (keyInfo.userAuthenticationValidityDurationSeconds == -1 || keyInfo.userAuthenticationValidityDurationSeconds == 0)
            ) {
                signatureBytes = triggerUserAuthFlow(alias, payloadBytes, opts, false).onFailure { return it }

            } else {
                try {
                    val algorithmResult = getSignatureAlgorithm(
                        privateKey,
                        opts.digest ?: throw SiliconException("DIGEST_NOT_SET", "Digest was null"),
                        opts.format
                    )
                    if (algorithmResult !is SiliconResult.Success) return algorithmResult
                    val alg = algorithmResult.data;

                    // Initialize the Signature Engine for ES256
                    val signatureEngine = Signature.getInstance(alg).apply {
                        initSign(privateKey)
                    }

                    // Pass the bytes into the Engine
                    signatureEngine.update(payloadBytes)

                    // Execute the hardware signature
                    signatureBytes = signatureEngine.sign()

                } catch (e: Exception) {
                    if (e.isUserAuthTimeout()) {
                        // The hardware requires user authentication.
                        signatureBytes = triggerUserAuthFlow(alias, payloadBytes, opts, true).onFailure { return it }
                    } else {
                        // Re-throw if not an auth timeout
                        throw e
                    }
                }
            }

            if (opts.format == SignFormat.P1363 &&
                privateKey.algorithm == KeyProperties.KEY_ALGORITHM_EC
            ) {
                signatureBytes = transcodeDerToP1363(
                    signatureBytes,
                    opts.digest ?: throw SiliconException("DIGEST_NOT_SET", "Digest was null")
                )
            }

            // Encode the raw signature bytes
            val base64Signature = encodeSignature(signatureBytes, opts.encoding)

            return SiliconResult.Success(base64Signature)

        } catch (e: KeyPermanentlyInvalidatedException) {
            // Occurs if the user enrolled new biometrics and invalidateOnNewBiometrics was true
            return SiliconResult.Failure(
                "KEY_INVALIDATED",
                "Key was permanently invalidated because biometric enrollment changed"
            )

        } catch (e: InvalidKeyException) {
            // TODO: Remove logs
            Log.d("RNSilicon", "Re-throw")
            Log.e("RNSilicon", e.toString())
            Log.e("RNSilicon", e.stackTraceToString())
            // Occurs if the key cannot be used for any reason (e.g., invalid encoding, wrong length, uninitialized, etc.)
            return SiliconResult.Failure(
                "INVALID_KEY",
                e.localizedMessage ?: "Key could not be used for this signing operation"
            )

        } catch (e: SiliconException) {
            throw e

        } catch (e: Exception) {
            return SiliconResult.Failure("SIGNING_FAILED", e.localizedMessage ?: "Unknown signing error", e.stackTraceToString())
        }
    }

    private suspend fun triggerUserAuthFlow(alias: String, payloadBytes: ByteArray, opts: SignOptions, hasTimeout: Boolean): SiliconResult<ByteArray> {
        // Grab the active UI context and cast it
        val activity = appContext.currentActivity as? FragmentActivity
            ?: return SiliconResult.Failure(
                "NO_ACTIVITY",
                "Current activity is null or not a FragmentActivity."
            )

        // Recreate the engine reference to pass into a fresh CryptoObject session
        val privateKey = keystore.getKey(alias, null) as PrivateKey

        val algorithmResult = getSignatureAlgorithm(
            privateKey,
            opts.digest ?: throw SiliconException("DIGEST_NOT_SET", "Digest was null"),
            opts.format
        ).onFailure { return it }

        val alg = algorithmResult

        // Delegate to the suspended UI Coroutine
        return if (hasTimeout) {
            promptAndSignWithTimeout(payloadBytes, privateKey, alg, activity)
        } else {
            promptAndSignCryptoObj(payloadBytes, privateKey, alg, activity)
        }
    }

    /**
     * Creates a CryptoObject, prompts user auth, and signs the payload using the CryptoObject
     *
     * NOTE: This is used for keys that have a timeout of -1
     */
    private suspend fun promptAndSignCryptoObj(
        payloadBytes: ByteArray,
        privateKey: PrivateKey,
        alg: String,
        activity: FragmentActivity
    ): SiliconResult<ByteArray> = withContext(Dispatchers.Main) {
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

                        // Resume the JS Promise with Success
                        continuation.resume(
                            SiliconResult.Success(signatureBytes)
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

            val signatureEngine = Signature.getInstance(alg).apply {
                initSign(privateKey)
            }

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

    /**
     * Prompts for biometric auth and only creates a new signature engine once auth is successful
     *
     * NOTE: This is used for keys that have a timeout >0
     */
    private suspend fun promptAndSignWithTimeout(
        payloadBytes: ByteArray,
        privateKey: PrivateKey,
        alg: String,
        activity: FragmentActivity
    ): SiliconResult<ByteArray> = withContext(Dispatchers.Main) {
        suspendCancellableCoroutine { continuation ->

            val executor = ContextCompat.getMainExecutor(activity)

            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    try {
                        val signatureEngine = Signature.getInstance(alg).apply {
                            initSign(privateKey)
                        }

                        // Sign the payload
                        signatureEngine.update(payloadBytes)
                        val signatureBytes = signatureEngine.sign()

                        // Resume the JS Promise with Success
                        continuation.resume(
                            SiliconResult.Success(signatureBytes)
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
            biometricPrompt.authenticate(promptInfo)
        }
    }

    // Gets the algorithm string to use for signing
    private fun getSignatureAlgorithm(key: PrivateKey, digest: SignDigest, format: SignFormat): SiliconResult<String> {
        return when (key.algorithm) {
            KeyProperties.KEY_ALGORITHM_EC -> when (digest) {
                SignDigest.SHA256 -> SiliconResult.Success("SHA256withECDSA")
            }

            KeyProperties.KEY_ALGORITHM_RSA -> when (digest) {
                SignDigest.SHA256 -> SiliconResult.Success("SHA256withRSA")
            }

            else -> SiliconResult.Failure("UNSUPPORTED_KEY_FAMILY", "Unsupported key family: ${key.algorithm}")
        }
    }

    // Encodes the signature with the specified encoding type
    private fun encodeSignature(bytes: ByteArray, encoding: SignEncoding): String {
        return when (encoding) {
            // Base64Url - use URL-safe chars, disable padding and the android default wrap
            SignEncoding.B64URL -> Base64.encodeToString(
                bytes,
                Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
            )

            // Base64 - disable the android default wrap
            SignEncoding.B64 -> Base64.encodeToString(bytes, Base64.NO_WRAP)
        }
    }

    /**
     * Parses an ASN.1 DER sequence produced by the Android Keystore and extracts
     * raw IEEE P1363 flat arrays (R || S) strictly aligned to the curve bounds.
     */
    fun transcodeDerToP1363(derSignature: ByteArray, digest: SignDigest): ByteArray {
        // Resolve exact target coordinate size based on requested digest algorithm
        val coordSize = when (digest) {
            SignDigest.SHA256 -> 32 // ES256
            // SignDigest.SHA384 -> 48 // ES384
            // SignDigest.SHA512 -> 66 // ES512
        }

        // If it doesn't start with the DER sequence header (0x30) treat the signature as malformed
        if (derSignature.isEmpty() || derSignature[0] != 0x30.toByte()) {
            throw SiliconException("MALFORMED_SIGNATURE", "Expected DER signature to start with sequence header (0x30)")
        }

        // Navigate Sequence Length Descriptors safely
        var offset = 1
        if (derSignature[offset] == 0x81.toByte()) {
            offset += 2 // Skip 0x81 marker and subsequent length byte
        } else {
            offset += 1 // Skip standard short-form length byte
        }

        // Extract R Coordinate payload
        if (derSignature[offset] != 0x02.toByte()) return derSignature
        val rLen = derSignature[offset + 1].toInt()
        val rStart = offset + 2
        val rBytes = derSignature.copyOfRange(rStart, rStart + rLen)

        // Extract S Coordinate payload
        offset = rStart + rLen
        if (derSignature[offset] != 0x02.toByte()) return derSignature
        val sLen = derSignature[offset + 1].toInt()
        val sStart = offset + 2
        val sBytes = derSignature.copyOfRange(sStart, sStart + sLen)

        // Force strict mathematical alignment
        val rAligned = alignCoordinate(rBytes, coordSize)
        val sAligned = alignCoordinate(sBytes, coordSize)

        // Concatenate flat array (R || S)
        return rAligned + sAligned
    }

    /**
     * Strips redundant DER sign bytes or injects missing left-padding zeroes
     * to guarantee a byte array exactly matches the target curve boundary.
     */
    private fun alignCoordinate(bytes: ByteArray, targetSize: Int): ByteArray {
        return when {
            bytes.size == targetSize -> bytes
            bytes.size > targetSize -> {
                // Array expanded due to prepended 0x00 sign byte. Strip from the left.
                bytes.copyOfRange(bytes.size - targetSize, bytes.size)
            }

            else -> {
                // Array contracted due to stripped leading zeroes. Left-pad to restore bounds.
                val padded = ByteArray(targetSize) // Natively initializes to pure 0x00 bytes
                bytes.copyInto(padded, destinationOffset = targetSize - bytes.size)
                padded
            }
        }
    }
}

/**
 * Determines if an Exception is fundamentally a Biometric/Auth timeout error,
 * digging through Android's nested causes and OEM quirks.
 */
fun Exception.isUserAuthTimeout(): Boolean {
    // pure-Android
    if (this is UserNotAuthenticatedException) return true

    // Keystore 2.0 (Android 12+)
    val cause = this.cause

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        if (cause is android.security.KeyStoreException) {
            // In Android API 33+, KeyStoreException has numericErrorCode.
            // Public error code 2 corresponds to ERROR_USER_NOT_AUTHENTICATED.
            // Internal Keystore code is -26 (KM_ERROR_KEY_USER_NOT_AUTHENTICATED).
            if (cause.numericErrorCode == 2) return true
        }
    }

    // If compiling below API 33, check the internal code signature
    if (cause?.message?.contains("code: -26") == true) return true

    // Lazy OEM (Raw InvalidKeyException)
    // We strictly scope this string check to InvalidKeyException to limit brittleness
    if (this is InvalidKeyException && this.message?.contains("user not authenticated", ignoreCase = true) == true) {
        return true
    }

    return false
}