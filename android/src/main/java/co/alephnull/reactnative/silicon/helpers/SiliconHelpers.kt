package co.alephnull.reactnative.silicon.helpers

import android.security.keystore.KeyProperties
import java.security.Key
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey

class SiliconHelpers {
    /**
     * This will work for passing both public and private key interfaces
     * Returns (algorithm, curve)
     */
    fun getKeyAlgorithm(key: Key): Pair<String, String?> {
        when (key.algorithm) {
            KeyProperties.KEY_ALGORITHM_EC -> {
                // Cast as ECKey to access the Elliptic Curve parameters
                val ecKey = key as ECKey

                // The field size tells us which curve it is
                val fieldSize = ecKey.params.curve.field.fieldSize

                val (alg, crv) = when (fieldSize) {
                    256 -> Pair("ES256", "P-256")
                    384 -> Pair("ES384", "P-384")
                    521 -> Pair("ES512", "P-521")
                    else -> Pair(key.algorithm, null)
                }

                return Pair(alg, crv)
            }

            KeyProperties.KEY_ALGORITHM_RSA -> {
                // Cast as RSAKey to get the params
                val rsaKey = key as RSAKey

                //  Extract the modulus and get its length in bits
                val keySize = rsaKey.modulus.bitLength()

                val alg = when {
                    keySize >= 4096 -> "RS512"
                    keySize >= 3072 -> "RS384"
                    keySize >= 2048 -> "RS256"
                    else -> throw Exception("RSA key size ($keySize) is too weak for secure JWTs")
                }

                return Pair(alg, null)
            }
        }

        return Pair(key.algorithm, null)
    }
}