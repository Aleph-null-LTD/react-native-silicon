package co.alephnull.reactnative.silicon.verifier

import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import co.alephnull.reactnative.silicon.PayloadByteArr
import co.alephnull.reactnative.silicon.PayloadText
import co.alephnull.reactnative.silicon.PayloadType
import co.alephnull.reactnative.silicon.SiliconErrorCode
import co.alephnull.reactnative.silicon.SiliconResult
import co.alephnull.reactnative.silicon.keystoremanager.SignaturePaddingAlgorithm
import co.alephnull.reactnative.silicon.onFailure
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec

class SiliconVerifier(private val keystore: KeyStore) {

    fun verify(payload: PayloadType, signature: PayloadType, opts: VerifyOptions): SiliconResult<Boolean> {
        try {
            val (algorithm, publicKey) = when {
                // If alias was supplied, get the pubkey from the keystore
                !opts.alias.isNullOrBlank() -> {
                    extractInternalKey(opts.alias as String, opts.algorithm).onFailure { return it }
                }

                // If a pubkey was supplied, parse it and use that
                !opts.pubkeyB64.isNullOrBlank() -> {
                    val requestedAlg = opts.algorithm
                        ?: return SiliconResult.Failure(
                            SiliconErrorCode.INVALID_ARGUMENT,
                            "opts.algorithm must be supplied when verifying with an external key"
                        )
                    extractExternalKey(opts.pubkeyB64 as String, requestedAlg).onFailure { return it }
                }

                else -> return SiliconResult.Failure(
                    SiliconErrorCode.INVALID_ARGUMENT,
                    "Either a local 'alias' or an external 'pubkey' must be supplied"
                )
            }

            val (jcaAlgo, baseKeyFamily) = when (algorithm) {
                // EC
                VerifyAlgorithm.ES256 -> Pair("SHA256withECDSA", KeyProperties.KEY_ALGORITHM_EC)
                VerifyAlgorithm.ES384 -> Pair("SHA384withECDSA", KeyProperties.KEY_ALGORITHM_EC)
                VerifyAlgorithm.ES512 -> Pair("SHA512withECDSA", KeyProperties.KEY_ALGORITHM_EC)

                // RSA PSS
                VerifyAlgorithm.PS256 -> Pair("SHA256withRSA/PSS", KeyProperties.KEY_ALGORITHM_RSA)
                VerifyAlgorithm.PS384 -> Pair("SHA384withRSA/PSS", KeyProperties.KEY_ALGORITHM_RSA)
                VerifyAlgorithm.PS512 -> Pair("SHA512withRSA/PSS", KeyProperties.KEY_ALGORITHM_RSA)

                // RSA PKCS1
                VerifyAlgorithm.RS256 -> Pair("SHA256withRSA", KeyProperties.KEY_ALGORITHM_RSA)
                VerifyAlgorithm.RS384 -> Pair("SHA384withRSA", KeyProperties.KEY_ALGORITHM_RSA)
                VerifyAlgorithm.RS512 -> Pair("SHA512withRSA", KeyProperties.KEY_ALGORITHM_RSA)
            }

            // Decode the inputs
            val payloadBytes = when (payload) {
                is PayloadText -> payload.text.toByteArray(Charsets.UTF_8)
                is PayloadByteArr -> payload.arr
            }

            val signatureBytes = when (signature) {
                is PayloadText -> Base64.decode(signature.text, Base64.DEFAULT)
                is PayloadByteArr -> signature.arr
            }

            val derSignatureBytes = ensureDerSignature(
                signatureBytes,
                baseKeyFamily,
                algorithm
            ).onFailure {
                return it
            }

            // Execute standard software JCA verification
            val isValid = Signature.getInstance(jcaAlgo).run {
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
                initVerify(publicKey)
                update(payloadBytes)
                verify(derSignatureBytes)
            }

            return SiliconResult.Success(isValid)

        } catch (e: Exception) {
            // Cryptographic parser exceptions (bad sig byte arrays, corrupted PEM strings)
            return SiliconResult.Failure(
                SiliconErrorCode.VERIFY_FAILED,
                e.localizedMessage ?: "Verification engine failure",
                e.stackTraceToString()
            )
        }
    }

    private fun extractInternalKey(alias: String, requestedAlgorithm: VerifyAlgorithm?): SiliconResult<Pair<VerifyAlgorithm, PublicKey>> {
        if (!keystore.containsAlias(alias)) {
            return SiliconResult.Failure(
                SiliconErrorCode.KEY_NOT_FOUND,
                "Local key alias '$alias' missing"
            )
        }
        val publicKey: PublicKey = keystore.getCertificate(alias).publicKey
            ?: return SiliconResult.Failure(
                SiliconErrorCode.VERIFY_FAILED,
                "Missing certificate for local key"
            )

        val factory = KeyFactory.getInstance(publicKey.algorithm)
        val keyInfo: KeyInfo = factory.getKeySpec(publicKey, KeyInfo::class.java)

        var alg: VerifyAlgorithm

        when (publicKey.algorithm) {
            KeyProperties.KEY_ALGORITHM_EC -> {
                // Cast as ECKey to access the Elliptic Curve parameters
                val ecKey = publicKey as ECKey

                // The field size tells us which curve it is
                val fieldSize = ecKey.params.curve.field.fieldSize

                if (requestedAlgorithm != null) {
                    // Algorithm was explicitly provided

                    var digest: String

                    when (requestedAlgorithm) {
                        VerifyAlgorithm.ES256 -> {
                            if (fieldSize != 256) {
                                return SiliconResult.Failure(
                                    SiliconErrorCode.INCOMPATIBLE,
                                    "key (${alias}) is an EC key and must use the algorithm that matches it's size (${VerifyAlgorithm.ES256.value})."
                                )
                            }
                            digest = KeyProperties.DIGEST_SHA256
                        }
                        VerifyAlgorithm.ES384 -> {
                            if (fieldSize != 384) {
                                return SiliconResult.Failure(
                                    SiliconErrorCode.INCOMPATIBLE,
                                    "key (${alias}) is an EC key and must use the algorithm that matches it's size (${VerifyAlgorithm.ES384.value})."
                                )
                            }
                            digest = KeyProperties.DIGEST_SHA384
                        }
                        VerifyAlgorithm.ES512 -> {
                            if (fieldSize != 521) {
                                return SiliconResult.Failure(
                                    SiliconErrorCode.INCOMPATIBLE,
                                    "key (${alias}) is an EC key and must use the algorithm that matches it's size (${VerifyAlgorithm.ES512.value})."
                                )
                            }
                            digest = KeyProperties.DIGEST_SHA512
                        }
                        else -> {
                            return SiliconResult.Failure(
                                SiliconErrorCode.INCOMPATIBLE,
                                "Cannot use $requestedAlgorithm with a non-EC key."
                            )
                        }
                    }

                    // Ensure the digest is on the allowed list
                    if (!keyInfo.digests.contains(digest)) {
                        return SiliconResult.Failure(
                            SiliconErrorCode.KEY_POLICY_VIOLATION,
                            "Key with alias $alias does not allow the $digest digest. Allowed digests: ${keyInfo.digests}"
                        )
                    }

                    alg = requestedAlgorithm

                } else {
                    // Algorithm was not provided, so determine the default algorithm based on the key size

                    var digest: String

                    when (fieldSize) {
                        256 -> {
                            alg = VerifyAlgorithm.ES256
                            digest = KeyProperties.DIGEST_SHA256
                        }
                        384 -> {
                            alg = VerifyAlgorithm.ES384
                            digest = KeyProperties.DIGEST_SHA384
                        }
                        521 -> {
                            alg = VerifyAlgorithm.ES512
                            digest = KeyProperties.DIGEST_SHA512
                        }
                        else -> {
                            return SiliconResult.Failure(SiliconErrorCode.UNSUPPORTED, "EC key size ($fieldSize) is not supported")
                        }
                    }

                    // Ensure the digest is on the allowed list
                    if (!keyInfo.digests.contains(digest)) {
                        return SiliconResult.Failure(
                            SiliconErrorCode.KEY_POLICY_VIOLATION,
                            "Could not use default verify algorithm for key ($alias). Please set the algorithm explicitly in the options."
                        )
                    }
                }

            }

            KeyProperties.KEY_ALGORITHM_RSA -> {
                // Cast as RSAKey to get the params
                val rsaKey = publicKey as RSAKey

                //  Extract the modulus and get its length in bits
                val keySize = rsaKey.modulus.bitLength()

                // Extract the allowed padding algorithms
                val allowedPaddings: Array<String> = keyInfo.signaturePaddings

                if (requestedAlgorithm != null) {
                    // Algorithm was explicitly provided

                    var digest: String

                    when (requestedAlgorithm) {
                        VerifyAlgorithm.RS256 -> {
                            if (!allowedPaddings.contains(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)) {
                                return SiliconResult.Failure(
                                    SiliconErrorCode.KEY_POLICY_VIOLATION,
                                    "Cannot use ${VerifyAlgorithm.RS256.value} with key ($alias). Please use ${VerifyAlgorithm.PS256.value}."
                                )
                            }
                            digest = KeyProperties.DIGEST_SHA256
                        }
                        VerifyAlgorithm.RS384 -> {
                            if (!allowedPaddings.contains(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)) {
                                return SiliconResult.Failure(
                                    SiliconErrorCode.KEY_POLICY_VIOLATION,
                                    "Cannot use ${VerifyAlgorithm.RS384.value} with key ($alias). Please use ${VerifyAlgorithm.PS384.value}."
                                )
                            }
                            digest = KeyProperties.DIGEST_SHA384
                        }
                        VerifyAlgorithm.RS512 -> {
                            if (!allowedPaddings.contains(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)) {
                                return SiliconResult.Failure(
                                    SiliconErrorCode.KEY_POLICY_VIOLATION,
                                    "Cannot use ${VerifyAlgorithm.RS512.value} with key ($alias). Please use ${VerifyAlgorithm.PS512.value}."
                                )
                            }
                            digest = KeyProperties.DIGEST_SHA512
                        }
                        VerifyAlgorithm.PS256 -> {
                            if (!allowedPaddings.contains(KeyProperties.SIGNATURE_PADDING_RSA_PSS)) {
                                return SiliconResult.Failure(
                                    SiliconErrorCode.KEY_POLICY_VIOLATION,
                                    "Cannot use ${VerifyAlgorithm.PS256.value} with key ($alias). Please use ${VerifyAlgorithm.RS256.value}."
                                )
                            }
                            digest = KeyProperties.DIGEST_SHA256
                        }
                        VerifyAlgorithm.PS384 -> {
                            if (!allowedPaddings.contains(KeyProperties.SIGNATURE_PADDING_RSA_PSS)) {
                                return SiliconResult.Failure(
                                    SiliconErrorCode.KEY_POLICY_VIOLATION,
                                    "Cannot use ${VerifyAlgorithm.PS384.value} with key ($alias). Please use ${VerifyAlgorithm.RS384.value}."
                                )
                            }
                            digest = KeyProperties.DIGEST_SHA384
                        }
                        VerifyAlgorithm.PS512 -> {
                            if (!allowedPaddings.contains(KeyProperties.SIGNATURE_PADDING_RSA_PSS)) {
                                return SiliconResult.Failure(
                                    SiliconErrorCode.KEY_POLICY_VIOLATION,
                                    "Cannot use ${VerifyAlgorithm.PS512.value} with key ($alias). Please use ${VerifyAlgorithm.RS512.value}."
                                )
                            }
                            digest = KeyProperties.DIGEST_SHA512
                        }
                        else -> {
                            return SiliconResult.Failure(
                                SiliconErrorCode.INCOMPATIBLE,
                                "Cannot use $requestedAlgorithm with a non-RSA key."
                            )
                        }
                    }

                    // Ensure the digest is on the allowed list
                    if (!keyInfo.digests.contains(digest)) {
                        return SiliconResult.Failure(
                            SiliconErrorCode.KEY_POLICY_VIOLATION,
                            "Key with alias $alias does not allow the $digest digest. Allowed digests: ${keyInfo.digests}"
                        )
                    }

                    alg = requestedAlgorithm

                } else {
                    // Algorithm was not provided, so determine the default algorithm based on the key size

                    var digest: String
                    var allowedPadding = if (allowedPaddings.contains(KeyProperties.SIGNATURE_PADDING_RSA_PSS)) {
                        SignaturePaddingAlgorithm.PSS
                    } else if (allowedPaddings.contains(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)) {
                        SignaturePaddingAlgorithm.PKCS1
                    } else {
                        return SiliconResult.Failure(
                            SiliconErrorCode.INTERNAL_ERROR,
                            "RSA key with alias '$alias' did not have any allowed padding algorithms."
                        )
                    }

                    when (keySize) {
                        2048, 2047 -> {
                            when (allowedPadding) {
                                SignaturePaddingAlgorithm.PSS -> {
                                    alg = VerifyAlgorithm.PS256
                                }
                                SignaturePaddingAlgorithm.PKCS1 -> {
                                    alg = VerifyAlgorithm.RS256
                                }
                            }
                            digest = KeyProperties.DIGEST_SHA256
                        }
                        3072, 3071 -> {
                            when (allowedPadding) {
                                SignaturePaddingAlgorithm.PSS -> {
                                    alg = VerifyAlgorithm.PS384
                                }
                                SignaturePaddingAlgorithm.PKCS1 -> {
                                    alg = VerifyAlgorithm.RS384
                                }
                            }
                            digest = KeyProperties.DIGEST_SHA384
                        }
                        4096, 4095 -> {
                            when (allowedPadding) {
                                SignaturePaddingAlgorithm.PSS -> {
                                    alg = VerifyAlgorithm.PS512
                                }
                                SignaturePaddingAlgorithm.PKCS1 -> {
                                    alg = VerifyAlgorithm.RS512
                                }
                            }
                            digest = KeyProperties.DIGEST_SHA512
                        }
                        else -> {
                            return SiliconResult.Failure(
                                SiliconErrorCode.UNSUPPORTED,
                                "RSA key size ($keySize) is not supported"
                            )
                        }
                    }

                    // Ensure the digest is on the allowed list
                    if (!keyInfo.digests.contains(digest)) {
                        return SiliconResult.Failure(
                            SiliconErrorCode.KEY_POLICY_VIOLATION,
                            "Key with alias $alias does not allow the $digest digest. Allowed digests: ${keyInfo.digests}"
                        )
                    }
                }
            }

            else -> {
                return SiliconResult.Failure(
                    SiliconErrorCode.UNSUPPORTED,
                    "Key family (${publicKey.algorithm}) is not supported for Verify."
                )
            }
        }

        return SiliconResult.Success(Pair(alg, publicKey))
    }

    private fun extractExternalKey(pubKeyB64: String, algorithm: VerifyAlgorithm): SiliconResult<Pair<VerifyAlgorithm, PublicKey>> {
        try {
            val keyBytes = Base64.decode(pubKeyB64, Base64.NO_WRAP)

            val baseKeyFamily = when (algorithm) {
                VerifyAlgorithm.ES256, VerifyAlgorithm.ES384, VerifyAlgorithm.ES512 -> KeyProperties.KEY_ALGORITHM_EC
                VerifyAlgorithm.PS256, VerifyAlgorithm.PS384, VerifyAlgorithm.PS512,
                VerifyAlgorithm.RS256, VerifyAlgorithm.RS384, VerifyAlgorithm.RS512 -> KeyProperties.KEY_ALGORITHM_RSA
            }

            val spec = X509EncodedKeySpec(keyBytes)
            val factory = KeyFactory.getInstance(baseKeyFamily)
            val pubKey = factory.generatePublic(spec)

            // Ensure that EC keys have the correct algorithm
            if (baseKeyFamily == KeyProperties.KEY_ALGORITHM_EC) {
                val ecKey = pubKey as ECKey
                val fieldSize = ecKey.params.curve.field.fieldSize

                when (fieldSize) {
                    256 -> {
                        if (algorithm != VerifyAlgorithm.ES256) {
                            return SiliconResult.Failure(
                                SiliconErrorCode.INCOMPATIBLE,
                                "Imported key is EC_P256 and must use the algorithm that matches it's size (${VerifyAlgorithm.ES256.value})."
                            )
                        }
                    }
                    384 -> {
                        if (algorithm != VerifyAlgorithm.ES384) {
                            return SiliconResult.Failure(
                                SiliconErrorCode.INCOMPATIBLE,
                                "Imported key is EC_P384 and must use the algorithm that matches it's size (${VerifyAlgorithm.ES384.value})."
                            )
                        }
                    }
                    521 -> {
                        if (algorithm != VerifyAlgorithm.ES512) {
                            return SiliconResult.Failure(
                                SiliconErrorCode.INCOMPATIBLE,
                                "Imported key is EC_P521 and must use the algorithm that matches it's size (${VerifyAlgorithm.ES512.value})."
                            )
                        }
                    }
                }
            }

            return SiliconResult.Success(Pair(algorithm, pubKey))

        } catch (e: Exception) {
            return SiliconResult.Failure(
                SiliconErrorCode.INVALID_ARGUMENT,
                "Failed to parse the provided public key. Ensure it is a valid X.509 SPKI string."
            )
        }
    }

    /**
     * Evaluates EC signatures and converts raw IEEE P1363 arrays into standard ASN.1 DER sequences.
     */
    private fun ensureDerSignature(signatureBytes: ByteArray, baseKeyFamily: String, algorithm: VerifyAlgorithm): SiliconResult<ByteArray> {
        // If it's RSA, return as-is
        if (baseKeyFamily != KeyProperties.KEY_ALGORITHM_EC || signatureBytes.isEmpty()) {
            return SiliconResult.Success(signatureBytes)
        }

        // Raw P1363 byte lengths will always be exact
        // ASN.1 DER lengths will be higher due to metadata headers, length descriptors, and padding bytes
        val isRawP1363 = when (algorithm) {
            VerifyAlgorithm.ES256 -> signatureBytes.size == 64
            //VerifyAlgorithm.ES384 -> signatureBytes.size == 96
            //VerifyAlgorithm.ES512 -> signatureBytes.size == 132 bytes

            // This should be caught by the guard at the top
            // But we include the else to satisfy the exhaustive when
            else -> return SiliconResult.Success(signatureBytes)
        }

        // If the signature is already DER then return as-is
        if (!isRawP1363) {
            // Should always start with DER Sequence tag (0x30)
            // If not then something went wrong and we treat the signature as malformed
            if (signatureBytes[0] != 0x30.toByte()) {
                return SiliconResult.Failure(
                    SiliconErrorCode.MALFORMED_DATA,
                    "Signature did not start with the DER Sequence tag (0x30)"
                )
            }

            return SiliconResult.Success(signatureBytes)
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
        val byteArr = ByteArrayOutputStream().apply {
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

        return SiliconResult.Success(byteArr)
    }
}