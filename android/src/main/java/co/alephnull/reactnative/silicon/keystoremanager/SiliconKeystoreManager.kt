package co.alephnull.reactnative.silicon.keystoremanager

import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import co.alephnull.reactnative.silicon.SiliconResult
import java.security.KeyPairGenerator
import android.util.Base64
import expo.modules.kotlin.AppContext
import java.security.InvalidAlgorithmParameterException
import java.security.KeyStore
import java.security.cert.Certificate

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

            // Encode and format the pubkey
            var b64Key = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
            if (opts.pubkeyFormat == PubkeyFormat.PEM) {
                b64Key = buildString {
                    append("-----BEGIN PUBLIC KEY-----\n")
                    append(b64Key)
                    append("-----END PUBLIC KEY-----")
                }
            }

            return SiliconResult.Success(b64Key);
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
                code = "DELETE_FAILED",
                message = e.localizedMessage ?: "Hardware key deletion failed for alias: $alias"
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
                code = "BULK_DELETE_FAILED",
                message = e.localizedMessage ?: "Failed to execute bulk key wipe: $count/$total deleted"
            )
        }
    }

    fun keyExists(alias: String): SiliconResult<Boolean> {
        try {
            val exists = keystore.containsAlias(alias)
            return SiliconResult.Success(exists)

        } catch (e: Exception) {
            return SiliconResult.Failure(
                code = "KEY_CHECK_FAILED",
                message = e.localizedMessage ?: "Failed to verify key existence for alias: $alias"
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
                code = "KEY_LIST_FAILED",
                message = e.localizedMessage ?: "Failed to list keys"
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
                code = "ATTEST_FAILED",
                message = e.localizedMessage ?: "Failed to extract certificate chain."
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
}