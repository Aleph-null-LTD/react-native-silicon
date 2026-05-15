package co.alephnull.reactnative.silicon.randomgen

import android.util.Base64
import co.alephnull.reactnative.silicon.SiliconResult
import java.security.SecureRandom

class SiliconRandomGen {
    fun generate(length: Int, format: RandomBytesFormat): SiliconResult<Any> {
        try {
            val randomBytes = ByteArray(length)

            // SecureRandom uses the hardware-seeded /dev/urandom by default
            SecureRandom().nextBytes(randomBytes)

            val formatted = when (format) {
                RandomBytesFormat.B64URL -> Base64.encodeToString(
                    randomBytes,
                    Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
                )

                RandomBytesFormat.B64 -> Base64.encodeToString(
                    randomBytes,
                    Base64.NO_WRAP
                )

                RandomBytesFormat.BYTES -> randomBytes
            }

            return SiliconResult.Success(formatted)

        } catch (e: Exception) {
            return SiliconResult.Failure(
                "RANDOM_GEN_FAILED",
                e.localizedMessage ?: "Failed to generate secure random bytes",
                e.stackTraceToString()
            )
        }
    }
}