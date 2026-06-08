package co.alephnull.reactnative.silicon.jose

import android.security.keystore.KeyProperties
import android.util.Base64
import co.alephnull.reactnative.silicon.SiliconErrorCode
import co.alephnull.reactnative.silicon.SiliconResult
import co.alephnull.reactnative.silicon.helpers.SiliconHelpers
import co.alephnull.reactnative.silicon.keystoremanager.PubkeyFormat
import co.alephnull.reactnative.silicon.keystoremanager.SiliconKeystoreManager
import java.math.BigInteger
import java.security.KeyStore
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class SiliconJose(private val keystore: KeyStore, private val siliconHelpers: SiliconHelpers) {

    fun getJwk(alias: String): SiliconResult<Map<String, Any>> {
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

            val jwk = when (certificate.publicKey.algorithm) {
                KeyProperties.KEY_ALGORITHM_EC -> constructEcJwk(certificate.publicKey)
                KeyProperties.KEY_ALGORITHM_RSA -> constructRsaJwk(certificate.publicKey)
                else -> return SiliconResult.Failure(
                    SiliconErrorCode.UNSUPPORTED,
                    "Key family ${certificate.publicKey.algorithm} is not supported for this function"
                )
            }

            return SiliconResult.Success(jwk)

        } catch (e: Exception) {
            return SiliconResult.Failure(
                SiliconErrorCode.GET_JWK_FAILED,
                e.localizedMessage ?: "Failed to extract JWK.",
                e.stackTraceToString()
            )
        }
    }

    private fun constructEcJwk(publicKey: PublicKey): Map<String, Any> {
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

        val (alg, crv) = siliconHelpers.getKeyAlgorithm(publicKey)

        if (crv == null) throw Exception("Unsupported EC curve size for JWK: $fieldSize")

        return mapOf(
            "kty" to "EC",
            "crv" to crv,
            "x" to formatCoordinate(ecKey.w.affineX),
            "y" to formatCoordinate(ecKey.w.affineY),
            "alg" to alg
        )
    }

    private fun constructRsaJwk(publicKey: PublicKey): Map<String, Any> {
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

        // crv will be null (because it's not an EC key)
        val (alg, crv) = siliconHelpers.getKeyAlgorithm(publicKey)

        return mapOf(
            "kty" to "RSA",
            "n" to formatRsaNumber(rsaKey.modulus),
            "e" to formatRsaNumber(rsaKey.publicExponent),
            "alg" to alg
        )
    }
}