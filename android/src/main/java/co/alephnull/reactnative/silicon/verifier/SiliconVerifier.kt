package co.alephnull.reactnative.silicon.verifier

import android.security.keystore.KeyProperties
import android.util.Base64
import co.alephnull.reactnative.silicon.PayloadByteArr
import co.alephnull.reactnative.silicon.PayloadText
import co.alephnull.reactnative.silicon.PayloadType
import co.alephnull.reactnative.silicon.SiliconException
import co.alephnull.reactnative.silicon.SiliconResult
import co.alephnull.reactnative.silicon.signer.SignAlgorithm
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

class SiliconVerifier(private val keystore: KeyStore) {

    fun verify(payload: PayloadType, signatureB64: String, opts: VerifyOptions): SiliconResult<Boolean> {
        try {
            val (jcaAlgo, baseKeyFamily) = when (opts.algorithm) {
                VerifyAlgorithm.ES256 -> Pair("SHA256withECDSA", KeyProperties.KEY_ALGORITHM_EC)
                null -> throw SiliconException("ALGORITHM_IS_NULL", "'opts.algorithm' was null");
            }

            val publicKey: PublicKey = when {
                // If alias was supplied, get the pubkey from the keystore
                !opts.alias.isNullOrBlank() -> {
                    if (!keystore.containsAlias(opts.alias)) {
                        return SiliconResult.Failure(
                            "KEY_NOT_FOUND",
                            "Local key alias '$opts.alias' missing"
                        )
                    }
                    keystore.getCertificate(opts.alias).publicKey
                        ?: return SiliconResult.Failure(
                            "NO_CERT",
                            "Missing certificate for local key"
                        )
                }

                // If a pubkey was supplied, parse it and use that
                !opts.pubkeyB64.isNullOrBlank() -> {
                    val keyBytes = Base64.decode(opts.pubkeyB64, Base64.NO_WRAP)

                    val spec = X509EncodedKeySpec(keyBytes)
                    val factory = KeyFactory.getInstance(baseKeyFamily)

                    factory.generatePublic(spec)
                }

                else -> throw SiliconException(
                    "INVALID_PARAMS",
                    "Either a local 'alias' or an external 'pubkey' must be supplied"
                )
            }

            // Decode the inputs
            val payloadBytes = when (payload) {
                is PayloadText -> payload.text.toByteArray(Charsets.UTF_8)
                is PayloadByteArr -> payload.arr
            }
            val signatureBytes = Base64.decode(signatureB64, Base64.DEFAULT)

            val derSignatureBytes = ensureDerSignature(
                signatureBytes,
                baseKeyFamily,
                opts.algorithm as VerifyAlgorithm // Will always be VerifyAlgorithm due to the guard at the top
            )

            // Execute standard software JCA verification
            val isValid = Signature.getInstance(jcaAlgo).run {
                initVerify(publicKey)
                update(payloadBytes)
                verify(derSignatureBytes)
            }

            return SiliconResult.Success(isValid)

        } catch (e: SiliconException) {
            // Re-throw our exceptions
            throw e

        } catch (e: Exception) {
            // Cryptographic parser exceptions (bad sig byte arrays, corrupted PEM strings)
            return SiliconResult.Failure(
                "VERIFICATION_FAILED",
                e.localizedMessage ?: "Verification engine failure",
                e.stackTraceToString()
            )
        }
    }

    /**
     * Evaluates EC signatures and converts raw IEEE P1363 arrays into standard ASN.1 DER sequences.
     */
    private fun ensureDerSignature(signatureBytes: ByteArray, baseKeyFamily: String, algorithm: VerifyAlgorithm): ByteArray {
        // If it's RSA, return as-is
        if (baseKeyFamily != KeyProperties.KEY_ALGORITHM_EC || signatureBytes.isEmpty()) {
            return signatureBytes
        }

        // Raw P1363 byte lengths will always be exact
        // ASN.1 DER lengths will be higher due to metadata headers, length descriptors, and padding bytes
        val isRawP1363 = when (algorithm) {
            VerifyAlgorithm.ES256 -> signatureBytes.size == 64
            //VerifyAlgorithm.ES384 -> signatureBytes.size == 96
            //VerifyAlgorithm.ES512 -> signatureBytes.size == 132 bytes

            // This should be caught by the guard at the top
            // But we include the else to satisfy the exhaustive when
            else -> return signatureBytes
        }

        // If the signature is already DER then return as-is
        if (!isRawP1363) {
            // Should always start with DER Sequence tag (0x30)
            // If not then something went wrong and we treat the signature as malformed
            if (signatureBytes[0] != 0x30.toByte()) {
                throw SiliconException("MALFORMED_SIGNATURE", "Signature did not start with the DER Sequence tag (0x30)")
            }

            return signatureBytes
        }

        // It is raw P1363. So split the array straight down the middle to isolate R and S.
        val halfLen = signatureBytes.size / 2
        val rBytes = signatureBytes.copyOfRange(0, halfLen)
        val sBytes = signatureBytes.copyOfRange(halfLen, signatureBytes.size)

        // BigInteger cleanly formats minimal DER integer alignment instantly
        val rDer = BigInteger(1, rBytes).toByteArray()
        val sDer = BigInteger(1, sBytes).toByteArray()

        // Calculate total internal payload length (excluding the Sequence header itself)
        // Formula: [0x02 Int Tag] + [R Len] + R + [0x02 Int Tag] + [S Len] + S
        val payloadLen = 1 + 1 + rDer.size + 1 + 1 + sDer.size

        // Assemble the strict ASN.1 DER payload structure:
        // [0x30 Sequence Tag] | [Total Len] | [0x02 Int Tag] | [R Len] | R | [0x02 Int Tag] | [S Len] | S
        return ByteArrayOutputStream().apply {
            write(0x30)

            // Handle standard ASN.1 length byte constraints
            if (payloadLen >= 128) {
                write(0x81) // Long-form marker: dictates exactly 1 subsequent length byte follows
                write(payloadLen) // Safe up to 255 bytes (ES512 payload evaluates to ~136 bytes)
            } else {
                write(payloadLen) // Short-form marker: standard direct sizing
            }

            // Write R integer block
            write(0x02)
            write(rDer.size)
            write(rDer)

            // Write S integer block
            write(0x02)
            write(sDer.size)
            write(sDer)
        }.toByteArray()
    }
}