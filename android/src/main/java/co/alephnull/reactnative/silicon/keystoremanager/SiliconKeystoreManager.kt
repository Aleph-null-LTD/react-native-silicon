package co.alephnull.reactnative.silicon.keystoremanager

import android.annotation.SuppressLint
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import co.alephnull.reactnative.silicon.SiliconResult
import java.security.KeyPairGenerator
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricManager
import co.alephnull.reactnative.silicon.SiliconErrorCode
import co.alephnull.reactnative.silicon.helpers.SiliconHelpers
import expo.modules.kotlin.AppContext
import java.io.Serializable
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.Key
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.UnrecoverableKeyException
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

class SiliconKeystoreManager(private val appContext: AppContext, private val keystore: KeyStore, private val siliconHelpers: SiliconHelpers) {

    fun generateKey(alias: String, opts: GenerateKeyOptions): SiliconResult<Unit> {
        if (keystore.containsAlias(alias)) {
            return SiliconResult.Failure(SiliconErrorCode.ALIAS_IN_USE, "A key with alias '$alias' already exists")
        }

        // If digests was not set, use the digest with the same size as the algorithm
        val digests: List<KeyDigest> = opts.android.digests ?: listOf(
            when (opts.android.algorithm) {
                KeyAlgorithm.EC_P256 -> KeyDigest.SHA256
                KeyAlgorithm.EC_P384 -> KeyDigest.SHA384
                KeyAlgorithm.EC_P521 -> KeyDigest.SHA512
                KeyAlgorithm.RSA_2048 -> KeyDigest.SHA256
                KeyAlgorithm.RSA_3072 -> KeyDigest.SHA384
                KeyAlgorithm.RSA_4096 -> KeyDigest.SHA512
            }
        )

        var useStrongBox: Boolean
        val requireStrongBox: Boolean
        var useTee: Boolean
        val allowSoftware: Boolean

        when (opts.android.hardwarePolicy) {
            HardwarePolicy.REQUIRE_STRONGBOX -> { useStrongBox = true; requireStrongBox = true; useTee = false; allowSoftware = false }
            HardwarePolicy.PREFER_STRONGBOX -> { useStrongBox = true; requireStrongBox = false; useTee = true; allowSoftware = false }
            HardwarePolicy.PREFER_STRONGBOX_ALLOW_SOFTWARE -> { useStrongBox = true; requireStrongBox = false; useTee = true; allowSoftware = true }
            HardwarePolicy.REQUIRE_TEE -> { useStrongBox = false; requireStrongBox = false; useTee = true; allowSoftware = false }
            HardwarePolicy.PREFER_TEE_ALLOW_SOFTWARE -> { useStrongBox = false; requireStrongBox = false; useTee = true; allowSoftware = true }
            HardwarePolicy.SOFTWARE_ONLY -> { useStrongBox = false; requireStrongBox = false; useTee = false; allowSoftware = true }
        }

        // Check if the device supports StrongBox
        val canUseStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                appContext.reactContext?.packageManager?.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE) == true

        // Fail-fast if StrongBox was required but not supported
        if (useStrongBox && requireStrongBox && !canUseStrongBox) {
            return SiliconResult.Failure(SiliconErrorCode.STRONGBOX_NOT_SUPPORTED, "StrongBox is not supported on this device")
        }

        // If StrongBox was preferred but not required,
        // and the device doesn't support it, disable it
        if (useStrongBox && !canUseStrongBox) {
            useStrongBox = false;
        }

        // Check if the device supports TEE
        val canUseTee = isTeeSupported()

        if (useTee && !canUseTee) {
            // If TEE is required but not supported - fail
            if (!allowSoftware) return SiliconResult.Failure(SiliconErrorCode.HARDWARE_NOT_AVAILABLE, "TEE is not supported on this device")

            // If TEE is preferred but software allowed - don't use TEE
            useTee = false
        }


        if (opts.attestChallenge != null) {
            if (allowSoftware) return SiliconResult.Failure(
                SiliconErrorCode.INVALID_ARGUMENT,
                "Hardware attestation cannot be performed on a software key. " +
                        "Set the hardware policy to ${HardwarePolicy.REQUIRE_STRONGBOX}, ${HardwarePolicy.PREFER_STRONGBOX}, or ${HardwarePolicy.REQUIRE_TEE} to enable it."
            )

            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
                return SiliconResult.Failure(
                    SiliconErrorCode.ATTEST_NOT_AVAILABLE,
                    "Key attestation is not supported on this device."
                )
            }
        }

        if (opts.purposes.contains(KeyPurpose.SIGN) || opts.purposes.contains(KeyPurpose.VERIFY)) {
            // If digests were not provided, determine the default based on the algorithm
            if (opts.android.digests.isNullOrEmpty()) {
                opts.android.digests = when (opts.android.algorithm) {
                    KeyAlgorithm.EC_P256, KeyAlgorithm.RSA_2048 -> listOf(KeyDigest.SHA256)
                    KeyAlgorithm.EC_P384, KeyAlgorithm.RSA_3072 -> listOf(KeyDigest.SHA384)
                    KeyAlgorithm.EC_P521, KeyAlgorithm.RSA_4096 -> listOf(KeyDigest.SHA512)
                }
            }

            val allowedDigests = opts.android.digests
                ?: return SiliconResult.Failure(SiliconErrorCode.INTERNAL_ERROR, "opts.android.digests was null after default value was set.")

            var isEC = false
            when (opts.android.algorithm) {
                KeyAlgorithm.EC_P256 -> {
                    if (!allowedDigests.contains(KeyDigest.SHA256)) {
                        return SiliconResult.Failure(
                            SiliconErrorCode.INVALID_ARGUMENT,
                            "EC keys cannot be used for signing with any digest other than the one that matches the size of the key. " +
                                    "Use ${KeyDigest.SHA256.value} for ${KeyAlgorithm.EC_P256.value} keys"
                        )
                    }
                    isEC = true
                }
                KeyAlgorithm.EC_P384 -> {
                    if (!allowedDigests.contains(KeyDigest.SHA384)) {
                        return SiliconResult.Failure(
                            SiliconErrorCode.INVALID_ARGUMENT,
                            "EC keys cannot be used for signing with any digest other than the one that matches the size of the key. " +
                                    "Use ${KeyDigest.SHA384.value} for ${KeyAlgorithm.EC_P384.value} keys"
                        )
                    }
                    isEC = true
                }
                KeyAlgorithm.EC_P521 -> {
                    if (!allowedDigests.contains(KeyDigest.SHA512)) {
                        return SiliconResult.Failure(
                            SiliconErrorCode.INVALID_ARGUMENT,
                            "EC keys cannot be used for signing with any digest other than the one that matches the size of the key. " +
                                    "Use ${KeyDigest.SHA512.value} for ${KeyAlgorithm.EC_P521.value} keys"
                        )
                    }
                    isEC = true
                }
                else -> {
                    // Do Nothing
                }
            }

            if (isEC && allowedDigests.size > 1) {
                return SiliconResult.Failure(
                    SiliconErrorCode.INVALID_ARGUMENT,
                    "EC keys cannot be used for signing with multiple digests. Use the digest that matches the key size."
                )
            }
        }

        // TODO: Extract the key generation logic into genHardwareKey and genSoftwareKey then call them depending on the bools above
        // For software keys - we omit "AndroidKeyStore" from the generator call and let android decide the provider
        // We need to persist the software keys ourselves
        /*
            if (useStrongbox || useTee) {
                genHardwareKey()
            } else {
                genSoftwareKey()
            }
         */

        val alg = when (opts.android.algorithm) {
            KeyAlgorithm.EC_P256, KeyAlgorithm.EC_P384, KeyAlgorithm.EC_P521 -> KeyProperties.KEY_ALGORITHM_EC
            KeyAlgorithm.RSA_2048, KeyAlgorithm.RSA_3072, KeyAlgorithm.RSA_4096 -> KeyProperties.KEY_ALGORITHM_RSA
        }

        // Initialize the Generator
        val kpg = KeyPairGenerator.getInstance(
            alg,
            "AndroidKeyStore"
        )

        // Iterate through purpose array and OR the values together
        var purpose = 0;
        for (p in opts.purposes) {
            when (p) {
                KeyPurpose.SIGN -> purpose = purpose or KeyProperties.PURPOSE_SIGN
                KeyPurpose.VERIFY -> purpose = purpose or KeyProperties.PURPOSE_VERIFY
                KeyPurpose.ENCRYPT -> purpose = purpose or KeyProperties.PURPOSE_ENCRYPT
                KeyPurpose.DECRYPT -> purpose = purpose or KeyProperties.PURPOSE_DECRYPT
                KeyPurpose.WRAP -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    purpose = purpose or KeyProperties.PURPOSE_WRAP_KEY
                } else {
                    return SiliconResult.Failure(SiliconErrorCode.UNSUPPORTED, "Purpose WRAP is not supported on this device")
                }
                KeyPurpose.AGREE -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    purpose = purpose or KeyProperties.PURPOSE_AGREE_KEY
                }  else {
                    return SiliconResult.Failure(SiliconErrorCode.UNSUPPORTED, "Purpose AGREE is not supported on this device")
                }
                //KeyPurpose.ATTEST -> purpose = purpose or KeyProperties.PURPOSE_ATTEST_KEY // NOTE: ATTEST has been removed to keep the API symmetric between platforms
            }
        }

        try {
            @SuppressLint("WrongConstant") // Suppress the lint on setDigests - we know that the values are correct here
            val parameterSpec = KeyGenParameterSpec.Builder(
                alias,
                purpose
            ).run {
                when (opts.android.algorithm) {
                    KeyAlgorithm.EC_P256 -> setAlgorithmParameterSpec(
                        java.security.spec.ECGenParameterSpec("secp256r1")
                    )
                    KeyAlgorithm.EC_P384 -> setAlgorithmParameterSpec(
                        java.security.spec.ECGenParameterSpec("secp384r1")
                    )
                    KeyAlgorithm.EC_P521 -> setAlgorithmParameterSpec(
                        java.security.spec.ECGenParameterSpec("secp521r1")
                    )
                    KeyAlgorithm.RSA_2048 -> setAlgorithmParameterSpec(
                        java.security.spec.RSAKeyGenParameterSpec(2048, java.security.spec.RSAKeyGenParameterSpec.F4)
                    )
                    KeyAlgorithm.RSA_3072 -> setAlgorithmParameterSpec(
                        java.security.spec.RSAKeyGenParameterSpec(3072, java.security.spec.RSAKeyGenParameterSpec.F4)
                    )
                    KeyAlgorithm.RSA_4096 -> setAlgorithmParameterSpec(
                        java.security.spec.RSAKeyGenParameterSpec(4096, java.security.spec.RSAKeyGenParameterSpec.F4)
                    )
                }

                // Map the digests to an array of the relevant constants
                val digestsArr: Array<String> = digests.mapNotNull { d ->
                    when (d) {
                        KeyDigest.SHA256 -> KeyProperties.DIGEST_SHA256
                        KeyDigest.SHA384 -> KeyProperties.DIGEST_SHA384
                        KeyDigest.SHA512 -> KeyProperties.DIGEST_SHA512
                    }
                }.toTypedArray()

                setDigests(*digestsArr)

                if (useStrongBox) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setIsStrongBoxBacked(true)
                    } else {
                        // Should never get here, this is just a failsafe
                        return SiliconResult.Failure(SiliconErrorCode.INTERNAL_ERROR, "Attempted to use StrongBox on unsupported SDK version (${Build.VERSION.SDK_INT})")
                    }
                }

                if (opts.attestChallenge != null) {
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
                        return SiliconResult.Failure(
                            SiliconErrorCode.ATTEST_NOT_AVAILABLE,
                            "Key attestation is not supported on this device"
                        )
                    }

                    setAttestationChallenge(opts.attestChallenge)
                }

                setUserAuthenticationRequired(opts.userAuth.require)
                if (opts.userAuth.require) {
                    // Get Context so we can check the biometrics capabilities
                    val context = appContext.reactContext
                        ?: return SiliconResult.Failure(SiliconErrorCode.GENERATE_KEY_FAILED, "Failed to get reactContext from AppContext.")


                    val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
                    if (!keyguardManager.isDeviceSecure) {
                        return SiliconResult.Failure(
                            SiliconErrorCode.DEVICE_NOT_SECURE,
                            "Cannot create an authenticated key. The device is not protected by a pin/password/pattern."
                        )
                    }

                    val biometricManager = BiometricManager.from(context)

                    // Hardware-backed keys require BIOMETRIC_STRONG
                    val canAuthenticateCode = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    when (canAuthenticateCode) {
                        BiometricManager.BIOMETRIC_SUCCESS -> {
                            // Hardware exists and user is enrolled - Proceed with generating the key
                        }
                        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                            // Hardware exists but user has not enrolled any biometrics
                            when (opts.userAuth.policy) {
                                AuthPolicy.BIOMETRICS_ONLY -> {
                                    return SiliconResult.Failure(
                                        SiliconErrorCode.BIOMERICS_NOT_ENROLLED,
                                        "User has not enrolled biometrics on this device."
                                    )
                                }
                                AuthPolicy.BIOMETRICS_OR_CREDENTIAL -> {
                                    // Use the passcode fallback
                                }
                            }
                        }
                        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
                        BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                            // The device physically lacks a strong sensor, or the sensor is broken
                            when (opts.userAuth.policy) {
                                AuthPolicy.BIOMETRICS_ONLY -> {
                                    return SiliconResult.Failure(
                                        SiliconErrorCode.BIOMERICS_NOT_AVAILABLE,
                                        "Strong biometrics are unavailable on this device."
                                    )
                                }
                                AuthPolicy.BIOMETRICS_OR_CREDENTIAL -> {
                                    // Use the passcode fallback
                                }
                            }
                        }
                        BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> {
                            // Vulnerability was found and the OEM disabled the sensor until the user updates their OS
                            when (opts.userAuth.policy) {
                                AuthPolicy.BIOMETRICS_ONLY -> {
                                    return SiliconResult.Failure(
                                        SiliconErrorCode.BIOMERICS_NOT_AVAILABLE,
                                        "The user must update their device to enable biometrics."
                                    )
                                }
                                AuthPolicy.BIOMETRICS_OR_CREDENTIAL -> {
                                    // Use the passcode fallback
                                }
                            }
                        }
                        else -> {
                            when (opts.userAuth.policy) {
                                AuthPolicy.BIOMETRICS_ONLY -> {
                                    return SiliconResult.Failure(
                                        SiliconErrorCode.BIOMERICS_NOT_AVAILABLE,
                                        "Biometrics are unavailable on this device: Code $canAuthenticateCode"
                                    )
                                }
                                AuthPolicy.BIOMETRICS_OR_CREDENTIAL -> {
                                    // Use the passcode fallback
                                }
                            }
                        }
                    }

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
                        if (opts.userAuth.policy == AuthPolicy.BIOMETRICS_ONLY) {
                            return SiliconResult.Failure(
                                SiliconErrorCode.BIOMERICS_NOT_AVAILABLE,
                                "Device is Android SDK version is < ${Build.VERSION_CODES.R}. Policy ${AuthPolicy.BIOMETRICS_ONLY.value} cannot be enforced."
                            )
                        }

                        val timeout = if (opts.userAuth.timeout == 0) {
                            -1 // -1 enforces authentication for every use, but OS fallback rules apply
                        } else {
                            opts.userAuth.timeout
                        }

                        @Suppress("DEPRECATION") // Suppress the deprecation - this is a fallback for old devices
                        setUserAuthenticationValidityDurationSeconds(timeout)
                    }
                }

                // Build the param spec
                build()
            }

            kpg.initialize(parameterSpec)

            // Generate the Key
            val keyPair = kpg.generateKeyPair()

            return SiliconResult.Success(Unit)
        } catch (e: InvalidAlgorithmParameterException) {
            return SiliconResult.Failure(
                SiliconErrorCode.GENERATE_KEY_FAILED,
                e.localizedMessage ?: "Failed to generate key due to invalid algorithm parameter"
            );
        } catch (e: Exception) {
            return SiliconResult.Failure(
                SiliconErrorCode.GENERATE_KEY_FAILED,
                e.localizedMessage ?: "Failed to generate key due to unknown error"
            )
        }
    }

    private fun isTeeSupported(): Boolean {
        val tempAlias = "co.alephnull.reactnative.silicon.temp.tee_hardware_check_key"

        try {
            // Generate a temporary symmetric key in the AndroidKeyStore
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            )

            keyGenerator.init(
                KeyGenParameterSpec.Builder(
                    tempAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                ).build()
            )

            val secretKey = keyGenerator.generateKey() as SecretKey

            // Extract the KeyInfo to inspect where the key actually lives
            val factory = KeyFactory.getInstance(secretKey.algorithm, "AndroidKeyStore")
            val keyInfo = factory.getKeySpec(secretKey, KeyInfo::class.java)

            // Verify if it resides inside secure hardware (TEE or StrongBox)
            val isHardwareBacked = keyInfo.isInsideSecureHardware

            // Clean up the temporary key so we don't leave garbage behind
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            keyStore.deleteEntry(tempAlias)

            return isHardwareBacked

        } catch (e: Exception) {
            // If anything fails (Keystore corrupted, unsupported algorithms, etc.),
            // we safely assume the hardware cannot support strict TEE requirements.
            return false
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
                SiliconErrorCode.DELETE_FAILED,
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
                SiliconErrorCode.DELETE_ALL_FAILED,
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
                SiliconErrorCode.KEY_EXISTS_FAILED,
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
                SiliconErrorCode.LIST_KEYS_FAILED,
                e.localizedMessage ?: "Failed to list keys",
                e.stackTraceToString()
            )
        }
    }

    fun getPubKey(alias: String, format: PubkeyFormat): SiliconResult<Serializable> {
        try {
            // Ensure the key exists
            if (!keystore.containsAlias(alias)) {
                return SiliconResult.Failure(SiliconErrorCode.KEY_NOT_FOUND, "No key exists for alias: '$alias'")
            }

            if (!keystore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry::class.java)) {
                return SiliconResult.Failure(
                    SiliconErrorCode.UNSUPPORTED,
                    "The key stored under alias '$alias' is a symmetric key. Public key extraction is only supported for asymmetric keypairs (RSA/EC)."
                )
            }

            val certificate = keystore.getCertificate(alias)
                ?: return SiliconResult.Failure(SiliconErrorCode.GET_PUB_KEY_FAILED, "No certificate chain found for key ($alias).")

            // certificate.publicKey.encoded will be DER-encoded X.509 SPKI by default
            val publicKey = when (format) {
                PubkeyFormat.B64 -> Base64.encodeToString(certificate.publicKey.encoded, Base64.NO_WRAP)

                PubkeyFormat.B64URL -> Base64.encodeToString(certificate.publicKey.encoded, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)

                PubkeyFormat.PEM -> {
                    val b64PubKey = Base64.encodeToString(certificate.publicKey.encoded, Base64.NO_WRAP)
                    // Insert a newline every 64 chars
                    val chunkedB64Pubkey = b64PubKey.chunked(64).joinToString("\n")

                    // Concat the header, key, and footer
                    buildString {
                        append("-----BEGIN PUBLIC KEY-----\n")
                        append(chunkedB64Pubkey + "\n")
                        append("-----END PUBLIC KEY-----")
                    }
                }

                PubkeyFormat.SPKI -> {
                    certificate.publicKey.encoded
                }
            }
            return SiliconResult.Success(publicKey)

        } catch (e: Exception) {
            return SiliconResult.Failure(
                SiliconErrorCode.GET_PUB_KEY_FAILED,
                e.localizedMessage ?: "Failed to extract public key.",
                e.stackTraceToString()
            )
        }
    }

    fun attestKey(alias: String): SiliconResult<Map<String, Any?>> {
        try {
            // Ensure the key exists
            if (!keystore.containsAlias(alias)) {
                return SiliconResult.Failure(SiliconErrorCode.KEY_NOT_FOUND, "No key exists for alias '$alias'")
            }

            // Query the Keystore for the certificate array
            val certChain = keystore.getCertificateChain(alias)
                ?: return SiliconResult.Failure(SiliconErrorCode.ATTEST_KEY_FAILED, "Key exists but has no certificate chain for alias '$alias'")

            if (!isKeyAttested(certChain)) {
                return SiliconResult.Failure(SiliconErrorCode.OPERATION_NOT_PERMITTED, "No attest challenge exists for key with alias '$alias'")
            }

            // Map the raw binary certificates to an array of PEM strings
            val pemChain = certChain.map { certificateToPem(it) }

            return SiliconResult.Success(
                mapOf(
                    "platform" to "ANDROID",
                    "certChain" to pemChain
                )
            )

        } catch (e: Exception) {
            return SiliconResult.Failure(
                SiliconErrorCode.ATTEST_KEY_FAILED,
                e.localizedMessage ?: "Failed to extract certificate chain.",
                e.stackTraceToString()
            )
        }
    }

    private fun isKeyAttested(certChain: Array<Certificate>): Boolean {
        // The Leaf certificate is always at index 0
        val leafCert = certChain[0] as? X509Certificate ?: return false

        // Query for the Android Key Attestation Extension OID
        val attestationExtension = leafCert.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")

        // If the extension exists, the key was generated with an attestation challenge
        return attestationExtension != null
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
                return SiliconResult.Failure(SiliconErrorCode.KEY_NOT_FOUND, "No key exists for alias: '$alias'")
            }

            // Grab the private key interface
            val key = keystore.getKey(alias, null)
                ?: return SiliconResult.Failure(SiliconErrorCode.GET_KEY_INFO_FAILED, "KeyInfo extraction requires a PrivateKey")

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
                    SiliconErrorCode.UNSUPPORTED,
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

            var (algorithm, curve) = siliconHelpers.getKeyAlgorithm(key)
            if (algorithm.startsWith("ES")) {
                algorithm = "EC"
            } else if (algorithm.startsWith("RS")) {
                algorithm = "RS"
            }

            val infoMap = mutableMapOf(
                "alias" to keyInfo.keystoreAlias,
                "algorithm" to algorithm,
                "curve" to curve,
                "keySize" to keyInfo.keySize,
                "digests" to keyInfo.digests,
                "securityLevel" to securityLevel,
                "purposes" to purposes,
                "isUserAuthRequired" to keyInfo.isUserAuthenticationRequired,
                "isInvalidatedByBiometricEnrollment" to keyInfo.isInvalidatedByBiometricEnrollment,
                "userAuthValidityDurationSecs" to keyInfo.userAuthenticationValidityDurationSeconds
            )
            // Remove curve from the map for non-EC keys
            if (infoMap["curve"] == null) infoMap.remove("curve")

            return SiliconResult.Success(infoMap)

        } catch (e: Exception) {
            return SiliconResult.Failure(
                SiliconErrorCode.GET_KEY_INFO_FAILED,
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
                else -> return SiliconResult.Failure(SiliconErrorCode.VALIDATE_KEY_FAILED, "Unrecognized Keystore entry type.")
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
                SiliconErrorCode.VALIDATE_KEY_FAILED,
                e.localizedMessage ?: "Key evaluation failed",
                e.stackTraceToString()
            )
        }
    }
}