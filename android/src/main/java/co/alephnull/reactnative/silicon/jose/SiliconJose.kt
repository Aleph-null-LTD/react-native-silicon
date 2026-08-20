package co.alephnull.reactnative.silicon.jose

import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import co.alephnull.reactnative.silicon.SiliconErrorCode
import co.alephnull.reactnative.silicon.SiliconResult
import co.alephnull.reactnative.silicon.helpers.SiliconHelpers
import co.alephnull.reactnative.silicon.keystoremanager.KeyAlgorithm
import co.alephnull.reactnative.silicon.onFailure
import co.alephnull.reactnative.silicon.signer.SignDigest
import expo.modules.core.utilities.ifNull
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class SiliconJose(private val keystore: KeyStore, private val siliconHelpers: SiliconHelpers) {

    fun getJwk(alias: String, digest: SignDigest?): SiliconResult<Map<String, Any>> {
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
                ?: return SiliconResult.Failure(SiliconErrorCode.GET_JWK_FAILED, "No certificate chain found for key '$alias'.")

            return when (certificate.publicKey.algorithm) {
                KeyProperties.KEY_ALGORITHM_EC -> constructEcJwk(certificate.publicKey, digest)
                KeyProperties.KEY_ALGORITHM_RSA -> constructRsaJwk(alias, certificate.publicKey, digest)
                else -> SiliconResult.Failure(
                    SiliconErrorCode.UNSUPPORTED,
                    "Key family ${certificate.publicKey.algorithm} is not supported for this function"
                )
            }

        } catch (e: Exception) {
            return SiliconResult.Failure(
                SiliconErrorCode.GET_JWK_FAILED,
                e.localizedMessage ?: "Failed to extract JWK.",
                e.stackTraceToString()
            )
        }
    }

    private fun constructEcJwk(publicKey: PublicKey, digest: SignDigest?): SiliconResult<Map<String, Any>> {
        val ecKey = publicKey as ECPublicKey
        val fieldSize = ecKey.params.curve.field.fieldSize
        val byteLength = (fieldSize + 7) / 8 // e.g., 256 bits = 32 bytes

        // Helper to strip leading zeros or pad with leading zeros to meet the exact curve size
        fun formatCoordinate(i: BigInteger): String {
            val bytes = i.toByteArray()
            val formattedBytes = when {
                bytes.size == byteLength -> bytes
                bytes.size > byteLength -> bytes.copyOfRange(bytes.size - byteLength, bytes.size) // Strip leading zero
                else -> { // Pad with leading zeros if it's too short
                    val padded = ByteArray(byteLength)
                    System.arraycopy(bytes, 0, padded, byteLength - bytes.size, bytes.size)
                    padded
                }
            }

            return Base64.encodeToString(formattedBytes, Base64.NO_WRAP or Base64.NO_PADDING or Base64.URL_SAFE)
        }

        val (alg, crv) = siliconHelpers.getKeyVerifyAlgorithm(publicKey)

        if (crv == null) return SiliconResult.Failure(
            SiliconErrorCode.UNSUPPORTED,
            "Unsupported EC curve size: $fieldSize"
        )

        digest?.let {
            when (digest) {
                SignDigest.SHA256 -> {
                    if (crv != "P-256") {
                        return SiliconResult.Failure(
                            SiliconErrorCode.INCOMPATIBLE,
                            "${KeyAlgorithm.EC_P256.value} keys must use the ${SignDigest.SHA256.value} digest."
                        )
                    }
                }
                SignDigest.SHA384 -> {
                    if (crv != "P-384") {
                        return SiliconResult.Failure(
                            SiliconErrorCode.INCOMPATIBLE,
                            "${KeyAlgorithm.EC_P384.value} keys must use the ${SignDigest.SHA384.value} digest."
                        )
                    }
                }
                SignDigest.SHA512 -> {
                    if (crv != "P-521") {
                        return SiliconResult.Failure(
                            SiliconErrorCode.INCOMPATIBLE,
                            "${KeyAlgorithm.EC_P521.value} keys must use the ${SignDigest.SHA512.value} digest."
                        )
                    }
                }
            }
        }

        return SiliconResult.Success(
            mapOf(
                "kty" to "EC",
                "crv" to crv,
                "x" to formatCoordinate(ecKey.w.affineX),
                "y" to formatCoordinate(ecKey.w.affineY),
                "alg" to alg
            )
        )
    }

    private fun constructRsaJwk(alias: String, publicKey: PublicKey, digest: SignDigest?): SiliconResult<Map<String, Any>> {
        val rsaKey = publicKey as RSAPublicKey

        // RSA doesn't have strict fixed-length padding requirements like EC,
        // but we still MUST strip the leading zero byte if Java added one.
        fun formatRsaNumber(i: BigInteger): String {
            val bytes = i.toByteArray()
            val unsignedBytes = if (bytes[0] == 0.toByte() && bytes.size > 1) {
                bytes.copyOfRange(1, bytes.size)
            } else {
                bytes
            }
            return Base64.encodeToString(unsignedBytes, Base64.NO_WRAP or Base64.NO_PADDING or Base64.URL_SAFE)
        }

        // Get the private key so we can check if the key uses PSS or PKCS1 padding
        val privateKey = keystore.getKey(alias, null) as? PrivateKey
            ?: return SiliconResult.Failure(
                SiliconErrorCode.KEY_NOT_FOUND,
                "Private key not found for alias: '$alias'"
            )
        val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
        val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
        val isPssPadding = keyInfo.signaturePaddings.toList().contains(KeyProperties.SIGNATURE_PADDING_RSA_PSS)

        // Extract the modulus and get its length in bits
        val keySize = rsaKey.modulus.bitLength()

        val alg = if (digest != null) {
            // Digest was explicitly set so set the corresponding algorithm
            when (digest) {
                SignDigest.SHA256 -> {
                    when (isPssPadding) {
                        true -> "PS256"
                        false -> "RS256"
                    }
                }
                SignDigest.SHA384 -> {
                    when (isPssPadding) {
                        true -> "PS384"
                        false -> "RS384"
                    }
                }
                SignDigest.SHA512 -> {
                    when (isPssPadding) {
                        true -> "PS512"
                        false -> "RS512"
                    }
                }
            }
        } else {
            // Digest was not set so use the algorithm that matches the key size
            // This corresponds to the same default algorithms we use when signing/verifying
            // RSA keys can be -1 below the expected size
            when {
                keySize >= 4095 -> {
                    when (isPssPadding) {
                        true -> "PS512"
                        false -> "RS512"
                    }
                }
                keySize >= 3071 -> {
                    when (isPssPadding) {
                        true -> "PS384"
                        false -> "RS384"
                    }
                }
                keySize >= 2047 -> {
                    when (isPssPadding) {
                        true -> "PS256"
                        false -> "RS256"
                    }
                }
                else -> return SiliconResult.Failure(
                    SiliconErrorCode.UNSUPPORTED,
                    "RSA key size $keySize is not supported for this function."
                )
            }
        }

        return SiliconResult.Success(
            mapOf(
                "kty" to "RSA",
                "n" to formatRsaNumber(rsaKey.modulus),
                "e" to formatRsaNumber(rsaKey.publicExponent),
                "alg" to alg
            )
        )
    }
}