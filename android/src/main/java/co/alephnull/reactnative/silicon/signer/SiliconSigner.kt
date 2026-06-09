package co.alephnull.reactnative.silicon.signer

import android.os.Build
import android.security.keystore.KeyInfo
import co.alephnull.reactnative.silicon.SiliconResult
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import co.alephnull.reactnative.silicon.PayloadByteArr
import co.alephnull.reactnative.silicon.PayloadText
import co.alephnull.reactnative.silicon.PayloadType
import co.alephnull.reactnative.silicon.SiliconErrorCode
import co.alephnull.reactnative.silicon.helpers.SiliconHelpers
import co.alephnull.reactnative.silicon.keystoremanager.SignaturePaddingAlgorithm
import co.alephnull.reactnative.silicon.onFailure
import co.alephnull.reactnative.silicon.verifier.VerifyAlgorithm
import expo.modules.kotlin.AppContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.security.InvalidKeyException
import java.security.KeyFactory
import kotlin.coroutines.resume
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

class SiliconSigner(private val appContext: AppContext, private val keystore: KeyStore, private val helpers: SiliconHelpers) {

    suspend fun sign(alias: String, payload: PayloadType, opts: SignOptions): SiliconResult<String> {
        try {
            // Verify that the key exists
            if (!keystore.containsAlias(alias)) {
                return SiliconResult.Failure(SiliconErrorCode.KEY_NOT_FOUND, "No key found for alias: $alias")
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
                ?: return SiliconResult.Failure(SiliconErrorCode.SIGN_FAILED, "Key is not a valid PrivateKey")

            val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)

            var jcaAlgo: String
            var algorithm: VerifyAlgorithm
            var digest: String
            var signDigest: SignDigest

            when (privateKey.algorithm) {
                KeyProperties.KEY_ALGORITHM_EC -> {
                    val ecKey = privateKey as ECKey
                    val fieldSize = ecKey.params.curve.field.fieldSize

                    if (opts.digest != null) {
                        // Digest was explicitly provided
                        when (opts.digest as SignDigest) {
                            SignDigest.SHA256 -> {
                                if (fieldSize != 256) {
                                    return SiliconResult.Failure(
                                        SiliconErrorCode.INCOMPATIBLE,
                                        "key ($alias) is an EC key and must use the digest that matches it's key size (${SignDigest.SHA256.value})."
                                    )
                                }
                                jcaAlgo = "SHA256withECDSA"
                                algorithm = VerifyAlgorithm.ES256
                                digest = KeyProperties.DIGEST_SHA256
                            }
                            SignDigest.SHA384 -> {
                                if (fieldSize != 384) {
                                    return SiliconResult.Failure(
                                        SiliconErrorCode.INCOMPATIBLE,
                                        "key ($alias) is an EC key and must use the digest that matches it's key size (${SignDigest.SHA384.value})."
                                    )
                                }
                                jcaAlgo = "SHA384withECDSA"
                                algorithm = VerifyAlgorithm.ES384
                                digest = KeyProperties.DIGEST_SHA384
                            }
                            SignDigest.SHA512 -> {
                                if (fieldSize != 521) {
                                    return SiliconResult.Failure(
                                        SiliconErrorCode.INCOMPATIBLE,
                                        "key ($alias) is an EC key and must use the digest that matches it's key size (${SignDigest.SHA512.value})."
                                    )
                                }
                                jcaAlgo = "SHA512withECDSA"
                                algorithm = VerifyAlgorithm.ES512
                                digest = KeyProperties.DIGEST_SHA512
                            }
                        }

                        // Ensure the digest is on the allowed list
                        if (!keyInfo.digests.contains(digest)) {
                            return SiliconResult.Failure(
                                SiliconErrorCode.KEY_POLICY_VIOLATION,
                                "Key with alias $alias does not allow the $digest digest. Allowed digests: ${keyInfo.digests}"
                            )
                        }
                        signDigest = opts.digest as SignDigest

                    } else {
                        // Digest was not provided - Determine default based on key size
                        when (fieldSize) {
                            256 -> {
                                jcaAlgo = "SHA256withECDSA"
                                algorithm = VerifyAlgorithm.ES256
                                digest = KeyProperties.DIGEST_SHA256
                                signDigest = SignDigest.SHA256
                            }
                            384 -> {
                                jcaAlgo = "SHA384withECDSA"
                                algorithm = VerifyAlgorithm.ES384
                                digest = KeyProperties.DIGEST_SHA384
                                signDigest = SignDigest.SHA384
                            }
                            521 -> {
                                jcaAlgo = "SHA512withECDSA"
                                algorithm = VerifyAlgorithm.ES512
                                digest = KeyProperties.DIGEST_SHA512
                                signDigest = SignDigest.SHA512
                            }
                            else -> {
                                return SiliconResult.Failure(
                                    SiliconErrorCode.UNSUPPORTED,
                                    "EC keys with size $fieldSize are not supported for sign."
                                )
                            }
                        }

                        // Ensure the digest is on the allowed list
                        if (!keyInfo.digests.contains(digest)) {
                            return SiliconResult.Failure(
                                SiliconErrorCode.KEY_POLICY_VIOLATION,
                                "Cannot use default digest ($digest) for key ($alias) as it is not in the allowed digests list (${keyInfo.digests}). Please set it explicitly in the options."
                            )
                        }
                    }

                }

                KeyProperties.KEY_ALGORITHM_RSA -> {
                    val rsaKey = privateKey as RSAKey
                    val keySize = rsaKey.modulus.bitLength()
                    val allowedPaddings: Array<String> = keyInfo.signaturePaddings

                    val allowedPadding = if (allowedPaddings.contains(KeyProperties.SIGNATURE_PADDING_RSA_PSS)) {
                        SignaturePaddingAlgorithm.PSS
                    } else if (allowedPaddings.contains(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)) {
                        SignaturePaddingAlgorithm.PKCS1
                    } else {
                        return SiliconResult.Failure(
                            SiliconErrorCode.INTERNAL_ERROR,
                            "RSA key with alias '$alias' did not have any allowed padding algorithms."
                        )
                    }

                    if (opts.digest != null) {
                        // Digest was explicitly provided
                        when (opts.digest as SignDigest) {
                            SignDigest.SHA256 -> {
                                when (allowedPadding) {
                                    SignaturePaddingAlgorithm.PSS -> {
                                        jcaAlgo = "SHA256withRSA/PSS"
                                        algorithm = VerifyAlgorithm.PS256
                                    }
                                    SignaturePaddingAlgorithm.PKCS1 -> {
                                        jcaAlgo = "SHA256withRSA"
                                        algorithm = VerifyAlgorithm.RS256
                                    }
                                }
                                digest = KeyProperties.DIGEST_SHA256
                            }
                            SignDigest.SHA384 -> {
                                when (allowedPadding) {
                                    SignaturePaddingAlgorithm.PSS -> {
                                        jcaAlgo = "SHA384withRSA/PSS"
                                        algorithm = VerifyAlgorithm.PS384
                                    }
                                    SignaturePaddingAlgorithm.PKCS1 -> {
                                        jcaAlgo = "SHA384withRSA"
                                        algorithm = VerifyAlgorithm.RS384
                                    }
                                }
                                digest = KeyProperties.DIGEST_SHA384
                            }
                            SignDigest.SHA512 -> {
                                when (allowedPadding) {
                                    SignaturePaddingAlgorithm.PSS -> {
                                        jcaAlgo = "SHA512withRSA/PSS"
                                        algorithm = VerifyAlgorithm.PS512
                                    }
                                    SignaturePaddingAlgorithm.PKCS1 -> {
                                        jcaAlgo = "SHA512withRSA"
                                        algorithm = VerifyAlgorithm.RS512
                                    }
                                }
                                digest = KeyProperties.DIGEST_SHA512
                            }
                        }

                        // Ensure the digest is on the allowed list
                        if (!keyInfo.digests.contains(digest)) {
                            return SiliconResult.Failure(
                                SiliconErrorCode.KEY_POLICY_VIOLATION,
                                "Key with alias $alias does not allow the $digest digest. Allowed digests: ${keyInfo.digests}"
                            )
                        }

                        signDigest = opts.digest as SignDigest

                    } else {
                        // Digest was not provided - Determine default based on key size
                        when (keySize) {
                            2048, 2047 -> {
                                when (allowedPadding) {
                                    SignaturePaddingAlgorithm.PSS -> {
                                        jcaAlgo = "SHA256withRSA/PSS"
                                        algorithm = VerifyAlgorithm.PS256
                                    }
                                    SignaturePaddingAlgorithm.PKCS1 -> {
                                        jcaAlgo = "SHA256withRSA"
                                        algorithm = VerifyAlgorithm.RS256
                                    }
                                }
                                digest = KeyProperties.DIGEST_SHA256
                                signDigest = SignDigest.SHA256
                            }
                            3072, 3071 -> {
                                when (allowedPadding) {
                                    SignaturePaddingAlgorithm.PSS -> {
                                        jcaAlgo = "SHA384withRSA/PSS"
                                        algorithm = VerifyAlgorithm.PS384
                                    }
                                    SignaturePaddingAlgorithm.PKCS1 -> {
                                        jcaAlgo = "SHA384withRSA"
                                        algorithm = VerifyAlgorithm.RS384
                                    }
                                }
                                digest = KeyProperties.DIGEST_SHA384
                                signDigest = SignDigest.SHA384
                            }
                            4096, 4095 -> {
                                when (allowedPadding) {
                                    SignaturePaddingAlgorithm.PSS -> {
                                        jcaAlgo = "SHA512withRSA/PSS"
                                        algorithm = VerifyAlgorithm.PS512
                                    }
                                    SignaturePaddingAlgorithm.PKCS1 -> {
                                        jcaAlgo = "SHA512withRSA"
                                        algorithm = VerifyAlgorithm.RS512
                                    }
                                }
                                digest = KeyProperties.DIGEST_SHA512
                                signDigest = SignDigest.SHA512
                            }
                            else -> {
                                return SiliconResult.Failure(
                                    SiliconErrorCode.UNSUPPORTED,
                                    "RSA keys with size $keySize are not supported for sign."
                                )
                            }
                        }

                        // Ensure the digest is on the allowed list
                        if (!keyInfo.digests.contains(digest)) {
                            return SiliconResult.Failure(
                                SiliconErrorCode.KEY_POLICY_VIOLATION,
                                "Cannot use default digest ($digest) for key ($alias) as it is not in the allowed digests list (${keyInfo.digests}). Please set it explicitly in the options."
                            )
                        }
                    }
                }

                else -> {
                    return SiliconResult.Failure(
                        SiliconErrorCode.UNSUPPORTED,
                        "Key family (${privateKey.algorithm}) is not supported for signing."
                    )
                }
            }

            var signatureBytes: ByteArray

            // Trigger the user auth flow if auth is required for every use
            if (keyInfo.isUserAuthenticationRequired &&
                (keyInfo.userAuthenticationValidityDurationSeconds == -1 || keyInfo.userAuthenticationValidityDurationSeconds == 0)
            ) {
                signatureBytes = triggerUserAuthFlow(alias, payloadBytes, opts, false, jcaAlgo, algorithm).onFailure { return it }

            } else {
                try {
                    // Initialize the Signature Engine for ES256
                    val signatureEngine = Signature.getInstance(jcaAlgo).apply {
                        when (algorithm) {
                            VerifyAlgorithm.PS256 -> setParameter(
                                PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
                            )
                            VerifyAlgorithm.PS384 -> setParameter(
                                PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)
                            )
                            VerifyAlgorithm.PS512 -> setParameter(
                                PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)
                            )
                            else -> {
                                // Do nothing - RS and ES families do not require manual parameter specs
                            }
                        }
                        initSign(privateKey)
                    }

                    // Pass the bytes into the Engine
                    signatureEngine.update(payloadBytes)

                    // Execute the hardware signature
                    signatureBytes = signatureEngine.sign()

                } catch (e: Exception) {
                    if (e.isUserAuthTimeout()) {
                        // The hardware requires user authentication.
                        signatureBytes = triggerUserAuthFlow(alias, payloadBytes, opts, true, jcaAlgo, algorithm).onFailure { return it }
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
                    signDigest
                ).onFailure {
                    return it
                }
            }

            // Encode the raw signature bytes
            val base64Signature = encodeSignature(signatureBytes, opts.encoding)

            return SiliconResult.Success(base64Signature)

        } catch (e: KeyPermanentlyInvalidatedException) {
            // Occurs if the user enrolled new biometrics and invalidateOnNewBiometrics was true
            return SiliconResult.Failure(
                SiliconErrorCode.KEY_INVALIDATED,
                "Key was permanently invalidated because biometric enrollment changed"
            )

        } catch (e: InvalidKeyException) {
            // Occurs if the key cannot be used for any reason (e.g., invalid encoding, wrong length, uninitialized, etc.)
            return SiliconResult.Failure(
                SiliconErrorCode.SIGN_FAILED,
                e.localizedMessage ?: "Key could not be used for this signing operation"
            )

        } catch (e: Exception) {
            return SiliconResult.Failure(SiliconErrorCode.SIGN_FAILED, e.localizedMessage ?: "Unknown signing error", e.stackTraceToString())
        }
    }

    private suspend fun triggerUserAuthFlow(alias: String, payloadBytes: ByteArray, opts: SignOptions, hasTimeout: Boolean, jcaAlgo: String, algorithm: VerifyAlgorithm): SiliconResult<ByteArray> {
        // Grab the active UI context and cast it
        val activity = appContext.currentActivity as? FragmentActivity
            ?: return SiliconResult.Failure(
                SiliconErrorCode.SIGN_FAILED,
                "Current activity is null or not a FragmentActivity."
            )

        // Recreate the engine reference to pass into a fresh CryptoObject session
        val privateKey = keystore.getKey(alias, null) as PrivateKey

        // Delegate to the suspended UI Coroutine
        return if (hasTimeout) {
            promptAndSignWithTimeout(payloadBytes, privateKey, jcaAlgo, algorithm, activity)
        } else {
            promptAndSignWithCryptoObj(payloadBytes, privateKey, jcaAlgo, algorithm, activity)
        }
    }

    /**
     * Creates a CryptoObject, prompts user auth, and signs the payload using the CryptoObject
     *
     * NOTE: This is used for keys that have a timeout of -1
     */
    private suspend fun promptAndSignWithCryptoObj(
        payloadBytes: ByteArray,
        privateKey: PrivateKey,
        jcaAlgo: String,
        algorithm: VerifyAlgorithm,
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
                            SiliconResult.Failure(SiliconErrorCode.SIGN_FAILED, e.message ?: "Failed post-auth", e.stackTraceToString()),
                        )
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    // Handles user cancellations, lockouts, or hardware errors
                    continuation.resume(handleAuthenticationError(errorCode, errString))
                }

                override fun onAuthenticationFailed() {
                    // Triggered on a bad biometric scan. The OS automatically keeps the UI open to retry
                    // so we do NOT resume/cancel the coroutine here
                }
            }

            val biometricPrompt = BiometricPrompt(activity, executor, callback)

            val signatureEngine = Signature.getInstance(jcaAlgo).apply {
                when (algorithm) {
                    VerifyAlgorithm.PS256 -> setParameter(
                        PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
                    )
                    VerifyAlgorithm.PS384 -> setParameter(
                        PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)
                    )
                    VerifyAlgorithm.PS512 -> setParameter(
                        PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)
                    )
                    else -> {
                        // Do nothing - RS and ES families do not require manual parameter specs
                    }
                }
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
        jcaAlgo: String,
        algorithm: VerifyAlgorithm,
        activity: FragmentActivity
    ): SiliconResult<ByteArray> = withContext(Dispatchers.Main) {
        suspendCancellableCoroutine { continuation ->

            val executor = ContextCompat.getMainExecutor(activity)

            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    try {
                        val signatureEngine = Signature.getInstance(jcaAlgo).apply {
                            when (algorithm) {
                                VerifyAlgorithm.PS256 -> setParameter(
                                    PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
                                )
                                VerifyAlgorithm.PS384 -> setParameter(
                                    PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)
                                )
                                VerifyAlgorithm.PS512 -> setParameter(
                                    PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)
                                )
                                else -> {
                                    // Do nothing - RS and ES families do not require manual parameter specs
                                }
                            }
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
                            SiliconResult.Failure(SiliconErrorCode.SIGN_FAILED, e.message ?: "Failed post-auth", e.stackTraceToString()),
                        )
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    // Handles user cancellations, lockouts, hardware errors
                    continuation.resume(handleAuthenticationError(errorCode, errString))
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

    private fun handleAuthenticationError(errorCode: Int, errString: CharSequence): SiliconResult<Nothing> {
        return when (errorCode) {
            // 13 - ERROR_NEGATIVE_BUTTON
            // 10 - ERROR_USER_CANCELED
            // 5 - ERROR_CANCELED
            13, 10, 5 -> SiliconResult.Failure(SiliconErrorCode.AUTH_CANCELED, errString.toString())

            // 7 - ERROR_LOCKOUT
            // 9 - ERROR_LOCKOUT_PERMANENT
            7, 9 -> SiliconResult.Failure(SiliconErrorCode.AUTH_LOCKED_OUT, errString.toString())

            // 11 - ERROR_NO_BIOMETRICS
            11 -> SiliconResult.Failure(SiliconErrorCode.BIOMETRICS_NOT_ENROLLED, errString.toString())

            // 14 - ERROR_NO_DEVICE_CREDENTIAL
            14 -> SiliconResult.Failure(SiliconErrorCode.DEVICE_NOT_SECURE, errString.toString())

            // All other errors are system errors
            else -> SiliconResult.Failure(SiliconErrorCode.SIGN_FAILED, errString.toString())
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
    fun transcodeDerToP1363(derSignature: ByteArray, digest: SignDigest): SiliconResult<ByteArray> {
        // Resolve exact target coordinate size based on requested digest algorithm
        val coordSize = when (digest) {
            SignDigest.SHA256 -> 32
            SignDigest.SHA384 -> 48
            SignDigest.SHA512 -> 66
        }

        // If it doesn't start with the DER sequence header (0x30) treat the signature as malformed
        if (derSignature.isEmpty() || derSignature[0] != 0x30.toByte()) {
            return SiliconResult.Failure(
                SiliconErrorCode.MALFORMED_DATA,
                "Expected DER signature to start with sequence header (0x30)"
            )
        }

        // Navigate Sequence Length Descriptors safely
        var offset = 1
        if (derSignature[offset] == 0x81.toByte()) {
            offset += 2 // Skip 0x81 marker and subsequent length byte
        } else {
            offset += 1 // Skip standard short-form length byte
        }

        // Extract R Coordinate payload
        if (derSignature[offset] != 0x02.toByte()) {
            return SiliconResult.Failure(
                SiliconErrorCode.MALFORMED_DATA,
                "Expected DER signature R coordinate to start with integer header (0x02)"
            )
        }
        val rLen = derSignature[offset + 1].toInt()
        val rStart = offset + 2
        val rBytes = derSignature.copyOfRange(rStart, rStart + rLen)

        // Extract S Coordinate payload
        offset = rStart + rLen
        if (derSignature[offset] != 0x02.toByte()) {
            return SiliconResult.Failure(
                SiliconErrorCode.MALFORMED_DATA,
                "Expected DER signature S coordinate to start with integer header (0x02)"
            )
        }
        val sLen = derSignature[offset + 1].toInt()
        val sStart = offset + 2
        val sBytes = derSignature.copyOfRange(sStart, sStart + sLen)

        // Force strict mathematical alignment
        val rAligned = alignCoordinate(rBytes, coordSize)
        val sAligned = alignCoordinate(sBytes, coordSize)

        // Concatenate flat array (R || S)
        return SiliconResult.Success(rAligned + sAligned)
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