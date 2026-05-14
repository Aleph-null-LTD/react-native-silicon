package co.alephnull.reactnative.silicon.keystoremanager

import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import co.alephnull.reactnative.silicon.SiliconResult
import java.security.KeyPairGenerator
import android.util.Base64
import expo.modules.kotlin.AppContext
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.UnrecoverableKeyException
import java.security.cert.Certificate
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

class SiliconKeystoreManager(private val appContext: AppContext, private val keystore: KeyStore) {

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
                KeyPurpose.WRAP -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    purpose or KeyProperties.PURPOSE_WRAP_KEY
                } else {
                    return SiliconResult.Failure("PURPOSE_WRAP_NOT_SUPPORTED", "Purpose ")
                }
                KeyPurpose.AGREE -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    purpose or KeyProperties.PURPOSE_AGREE_KEY
                }  else {
                    return SiliconResult.Failure("PURPOSE_AGREE_NOT_SUPPORTED", "Purpose ")
                }
                KeyPurpose.ATTEST -> purpose or KeyProperties.PURPOSE_ATTEST_KEY
            }
        }

        try {
            @SuppressLint("WrongConstant") // Suppress the lint on setDigests - we know that the values are correct here
            val parameterSpec = KeyGenParameterSpec.Builder(
                alias,
                purpose
            ).run {
                when (opts.android.algorithm) {
                    KeyAlgorithm.ES256 -> setAlgorithmParameterSpec(
                        java.security.spec.ECGenParameterSpec(
                            "secp256r1"
                        )
                    ) // ES256
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

                if (opts.attestChallenge != null) {
                    setAttestationChallenge(opts.attestChallenge?.toByteArray(Charsets.UTF_8))
                }

                setUserAuthenticationRequired(opts.userAuth.require)

                if (opts.userAuth.require) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        val authFlags = when (opts.userAuth.policy) {
                            AuthPolicy.BIOMETRICS_ONLY -> KeyProperties.AUTH_BIOMETRIC_STRONG
                            AuthPolicy.BIOMETRICS_OR_CREDENTIAL -> KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                        }

                        setUserAuthenticationParameters(opts.userAuth.timeout, authFlags)

                        if (opts.userAuth.invalidateOnEnrollment) {
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

            // Encode and format the pubkey
            var pubkey = when (opts.pubkeyFormat) {
                PubkeyFormat.PEM -> buildString {
                    append("-----BEGIN PUBLIC KEY-----\n")
                    // Line breaks are required for PEM keys
                    append(Base64.encodeToString(keyPair.public.encoded, Base64.DEFAULT))
                    append("-----END PUBLIC KEY-----")
                }

                // Disable line breaks for raw Base64
                PubkeyFormat.B64 -> Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
            }

            return SiliconResult.Success(pubkey);
        } catch (e: InvalidAlgorithmParameterException) {
            return SiliconResult.Failure(
                "INVALID_ALGORITHM_PARAMETER",
                e.localizedMessage ?: "Failed to generate key due to invalid algorithm parameter"
            );
        }
    }

    fun deleteKey(alias: String): SiliconResult<Boolean> {
        try {
            if (!keystore.containsAlias(alias)) {
                return SiliconResult.Success(false)
            }

            keystore.deleteEntry(alias)

            return SiliconResult.Success(true)

        } catch (e: Exception) {
            // Catches underlying KeyStoreException if the hardware state is locked/corrupted
            return SiliconResult.Failure(
                "DELETE_FAILED",
                e.localizedMessage ?: "Hardware key deletion failed for alias: $alias",
                e.stackTraceToString()
            )
        }
    }

    fun deleteAllKeys(prefix: String? = null): SiliconResult<Int> {
        var total = 0
        var count = 0

        try {
            val aliases = keystore.aliases().toList()

            total = aliases.count()

            for (alias in aliases) {
                if (prefix == null || alias.startsWith(prefix)) {
                    keystore.deleteEntry(alias)
                    count++
                }
            }

            return SiliconResult.Success(count)

        } catch (e: Exception) {
            return SiliconResult.Failure(
                "BULK_DELETE_FAILED",
                e.localizedMessage ?: "Failed to execute bulk key wipe: $count/$total deleted",
                e.stackTraceToString()
            )
        }
    }

    fun keyExists(alias: String): SiliconResult<Boolean> {
        try {
            val exists = keystore.containsAlias(alias)
            return SiliconResult.Success(exists)

        } catch (e: Exception) {
            return SiliconResult.Failure(
                "KEY_CHECK_FAILED",
                e.localizedMessage ?: "Failed to verify key existence for alias: $alias",
                e.stackTraceToString()
            )
        }
    }

    fun listKeys(prefix: String?): SiliconResult<List<String>> {
        try {
            val aliases = keystore.aliases().toList()

            val filtered = if (prefix != null) {
                aliases.filter { it.startsWith(prefix) }
            } else {
                aliases
            }
            return SiliconResult.Success(filtered)

        } catch (e: Exception) {
            return SiliconResult.Failure(
                "KEY_LIST_FAILED",
                e.localizedMessage ?: "Failed to list keys",
                e.stackTraceToString()
            )
        }
    }

    fun getPubKey(alias: String, format: PubkeyFormat): SiliconResult<String> {
        try {
            // Ensure the key exists
            if (!keystore.containsAlias(alias)) {
                return SiliconResult.Failure("KEY_NOT_FOUND", "No key exists for alias: '$alias'")
            }

            if (!keystore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry::class.java)) {
                return SiliconResult.Failure(
                    "UNSUPPORTED_KEY_FAMILY",
                    "The key stored under alias '$alias' is a symmetric key. Public key extraction is only supported for asymmetric keypairs (RSA/EC)."
                )
            }

            val certificate = keystore.getCertificate(alias)
                ?: return SiliconResult.Failure("NO_CERT", "No certificate chain found for key '$alias'.")

            val publicKey = when (format) {
                PubkeyFormat.B64 -> Base64.encodeToString(certificate.publicKey.encoded, Base64.NO_WRAP)

                PubkeyFormat.PEM -> buildString {
                    append("-----BEGIN PUBLIC KEY-----\n")
                    append(Base64.encodeToString(certificate.publicKey.encoded, Base64.DEFAULT))
                    append("-----END PUBLIC KEY-----")
                }
            }
            return SiliconResult.Success(publicKey)

        } catch (e: Exception) {
            return SiliconResult.Failure(
                "GET_PUB_KEY_FAILED",
                e.localizedMessage ?: "Failed to extract public key.",
                e.stackTraceToString()
            )
        }
    }

    fun attestKey(alias: String): SiliconResult<List<String>> {
        try {
            // Ensure the key exists
            if (!keystore.containsAlias(alias)) {
                return SiliconResult.Failure("KEY_NOT_FOUND", "No key exists for alias: '$alias'")
            }

            // Query the Keystore for the certificate array
            val certChain = keystore.getCertificateChain(alias)
                ?: return SiliconResult.Failure("NO_CERT_CHAIN", "Key exists but has no certificate chain")

            // Map the raw binary certificates to an array of PEM strings
            val pemChain = certChain.map { certificateToPem(it) }

            return SiliconResult.Success(pemChain)

        } catch (e: Exception) {
            return SiliconResult.Failure(
                "ATTEST_FAILED",
                e.localizedMessage ?: "Failed to extract certificate chain.",
                e.stackTraceToString()
            )
        }
    }

    private fun certificateToPem(certificate: Certificate): String {
        // Standard Base64 encoding with line breaks formatted for standard X.509 parsers
        val encodedCert = Base64.encodeToString(certificate.encoded, Base64.DEFAULT)
        return buildString {
            append("-----BEGIN CERTIFICATE-----\n")
            append(encodedCert)
            append("-----END CERTIFICATE-----")
        }
    }

    fun getKeyInfo(alias: String): SiliconResult<Map<String, Any?>> {
        try {
            // Ensure the key exists
            if (!keystore.containsAlias(alias)) {
                return SiliconResult.Failure("KEY_NOT_FOUND", "No key exists for alias: '$alias'")
            }

            // Grab the private key interface
            val key = keystore.getKey(alias, null)
                ?: return SiliconResult.Failure("KEY_LOAD_FAILED", "KeyInfo extraction requires a PrivateKey")

            // Smart-cast to the correct JCA engine to extract the underlying OS KeyInfo spec
            val keyInfo: KeyInfo = when (key) {
                is PrivateKey -> {
                    val factory = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
                    factory.getKeySpec(key, KeyInfo::class.java)
                }
                is SecretKey -> {
                    val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
                    factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
                }
                else -> return SiliconResult.Failure(
                    "UNSUPPORTED_KEY_FAMILY",
                    "KeyInfo extraction is not supported for key class: ${key.javaClass.simpleName}"
                )
            }

            // Resolve the physical isolation layer securely across Android OS boundaries
            val securityLevel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "STRONGBOX"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                    else -> "SOFTWARE"
                }
            } else {
                @Suppress("Deprecation")
                if (keyInfo.isInsideSecureHardware) "TEE" else "SOFTWARE"
            }

            val purposes = mutableListOf<String>()

            for (mask in listOf(1,2,4,8,16,32,64,128)) {
                when (mask and keyInfo.purposes) {
                    KeyProperties.PURPOSE_SIGN -> purposes.add("SIGN")
                    KeyProperties.PURPOSE_VERIFY -> purposes.add("VERIFY")
                    KeyProperties.PURPOSE_ENCRYPT -> purposes.add("ENCRYPT")
                    KeyProperties.PURPOSE_DECRYPT -> purposes.add("DECRYPT")
                    KeyProperties.PURPOSE_WRAP_KEY -> purposes.add("WRAP")
                    KeyProperties.PURPOSE_AGREE_KEY -> purposes.add("AGREE")
                    KeyProperties.PURPOSE_ATTEST_KEY -> purposes.add("ATTEST")
                    else -> continue
                }
            }

            val infoMap = mapOf(
                "alias" to keyInfo.keystoreAlias,
                "algorithm" to key.algorithm,
                "keySize" to keyInfo.keySize,
                "digests" to keyInfo.digests,
                "securityLevel" to securityLevel,
                "purposes" to purposes,
                "isUserAuthRequired" to keyInfo.isUserAuthenticationRequired,
                "isInvalidatedByBiometricEnrollment" to keyInfo.isInvalidatedByBiometricEnrollment,
                "userAuthValidityDurationSecs" to keyInfo.userAuthenticationValidityDurationSeconds
            )
            return SiliconResult.Success(infoMap)

        } catch (e: Exception) {
            return SiliconResult.Failure(
                "GET_KEY_INFO_FAILED",
                e.localizedMessage ?: "Failed to read KeyInfo.",
                e.stackTraceToString()
            )
        }
    }

    fun validateKey(alias: String): SiliconResult<String> {
        try {
            // Ensure the key exists
            if (!keystore.containsAlias(alias)) {
                return SiliconResult.Success("MISSING")
            }

            when (val entry = keystore.getEntry(alias, null)) {
                is KeyStore.PrivateKeyEntry -> {
                    // ASYMMETRIC DRY-RUN
                    val privateKey = entry.privateKey

                    // Extract the spec to query authorized OS constraints
                    val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
                    val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)

                    // Safely resolve the first authorized digest
                    val firstDigest = keyInfo.digests.firstOrNull() ?: KeyProperties.DIGEST_SHA256
                    val digestPrefix = when (firstDigest) {
                        KeyProperties.DIGEST_NONE -> "NONE"
                        KeyProperties.DIGEST_MD5 -> "MD5"
                        KeyProperties.DIGEST_SHA1 -> "SHA1"
                        KeyProperties.DIGEST_SHA224 -> "SHA224"
                        KeyProperties.DIGEST_SHA256 -> "SHA256"
                        KeyProperties.DIGEST_SHA384 -> "SHA384"
                        KeyProperties.DIGEST_SHA512 -> "SHA512"
                        else -> "SHA256"
                    }

                    // Check for specific RSA PSS padding constraints
                    val isEC = privateKey.algorithm == KeyProperties.KEY_ALGORITHM_EC
                    val isPssOnly = if (isEC) {
                        false
                    } else {
                        // Unwrap the platform array
                        val paddings = keyInfo.signaturePaddings

                        KeyProperties.SIGNATURE_PADDING_RSA_PSS in paddings &&
                                KeyProperties.SIGNATURE_PADDING_RSA_PKCS1 !in paddings
                    }

                    // Assemble the exact, authorized JCA algorithm string
                    val jcaAlgo = when {
                        isEC -> "${digestPrefix}withECDSA"
                        isPssOnly -> "${digestPrefix}withRSA/PSS"
                        else -> "${digestPrefix}withRSA"
                    }

                    try {
                        // Execute dry-run memory mapping
                        Signature.getInstance(jcaAlgo).apply {
                            initSign(privateKey)
                        }
                    } catch (e: KeyPermanentlyInvalidatedException) {
                        throw e // Let it bubble up to the core invalidation trap
                    } catch (e: InvalidKeyException) {
                        // Safe fallback trap: If a highly complex padding parameter required custom specs,
                        // Keystore throws standard InvalidKeyException. Because it did NOT throw
                        // KeyPermanentlyInvalidatedException, the material is certified intact.
                    }
                }
                is KeyStore.SecretKeyEntry -> {
                    // SYMMETRIC DRY-RUN
                    val secretKey = entry.secretKey

                    if (secretKey.algorithm.startsWith("Hmac")) {
                        Mac.getInstance(secretKey.algorithm).apply { init(secretKey) }
                    } else {
                        // Extract KeyInfo to map authorized transformation parameters
                        val factory = SecretKeyFactory.getInstance(secretKey.algorithm, "AndroidKeyStore")
                        val keyInfo = factory.getKeySpec(secretKey, KeyInfo::class.java) as KeyInfo

                        val blockMode = keyInfo.blockModes.firstOrNull() ?: KeyProperties.BLOCK_MODE_GCM
                        val padding = keyInfo.encryptionPaddings.firstOrNull() ?: KeyProperties.ENCRYPTION_PADDING_NONE

                        val modeStr = if (blockMode == KeyProperties.BLOCK_MODE_CBC) "CBC" else "GCM"
                        val padStr = if (padding == KeyProperties.ENCRYPTION_PADDING_PKCS7) "PKCS7Padding" else "NoPadding"

                        val cipher = Cipher.getInstance("${secretKey.algorithm}/$modeStr/$padStr")

                        try {
                            // Initialize the Cipher. Try ENCRYPT if authorized, otherwise DECRYPT.
                            if ((keyInfo.purposes and KeyProperties.PURPOSE_ENCRYPT) != 0) {
                                cipher.init(Cipher.ENCRYPT_MODE, secretKey)
                            } else {
                                // DECRYPT_MODE without IV parameters throws a standard InvalidKeyException,
                                // but AndroidKeyStore SPI evaluates OS biometric integrity BEFORE checking params.
                                cipher.init(Cipher.DECRYPT_MODE, secretKey)
                            }
                        } catch (e: KeyPermanentlyInvalidatedException) {
                            throw e // Explicitly re-throw to hit the core invalidation block below
                        } catch (e: InvalidKeyException) {
                            // Swallowed safely - Missing IV params or minor transform mismatch.
                            // Because it didn't throw KeyPermanentlyInvalidatedException, the material is healthy.
                        }
                    }
                }
                else -> return SiliconResult.Failure("KEY_VALIDATION_FAILED", "Unrecognized Keystore entry type.")
            }

            // If we made it here without throwing, the key material is 100% healthy
            return SiliconResult.Success("VALID")

        } catch (e: KeyPermanentlyInvalidatedException) {
            // The user enrolled new biometrics. Key is cryptographically dead.
            return SiliconResult.Success("INVALIDATED")

        } catch (e: UnrecoverableKeyException) {
            // The key is unrecoverable
            return SiliconResult.Success("UNRECOVERABLE")

        } catch (e: Exception) {
            // Catch-all for generic system/hardware state corruption
            return SiliconResult.Failure(
                "KEY_VALIDATION_FAILED",
                e.localizedMessage ?: "Key evaluation failed",
                e.stackTraceToString()
            )
        }
    }
}