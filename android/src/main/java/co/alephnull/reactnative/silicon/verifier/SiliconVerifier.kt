package co.alephnull.reactnative.silicon.verifier

import android.security.keystore.KeyProperties
import android.util.Base64
import co.alephnull.reactnative.silicon.PayloadByteArr
import co.alephnull.reactnative.silicon.PayloadText
import co.alephnull.reactnative.silicon.PayloadType
import co.alephnull.reactnative.silicon.SiliconException
import co.alephnull.reactnative.silicon.SiliconResult
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
                null -> throw SiliconException("ALG_IS_NULL", "'opts.algorithm' was null");
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

            // Execute standard software JCA verification
            val isValid = Signature.getInstance(jcaAlgo).run {
                initVerify(publicKey)
                update(payloadBytes)
                verify(signatureBytes)
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
}