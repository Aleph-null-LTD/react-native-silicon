package co.alephnull.reactnative.silicon

/**
 * A standardized result for the Silicon bridge.
 * [T] is the type of data returned on success.
 */
sealed class SiliconResult<out T> {
    data class Success<out T>(val data: T) : SiliconResult<T>()

    data class Failure(
        val code: String,
        val message: String,
        val nativeStack: String? = null
    ) : SiliconResult<Nothing>()

    /**
     * Converts the Result into a Map that the Expo Bridge can serialize to JS.
     */
    fun toBridgeMap(): Map<String, Any?> {
        return when (this) {
            is Success -> mapOf(
                "success" to true,
                "data" to data
            )
            is Failure -> mapOf(
                "success" to false,
                "errorCode" to code,
                "errorMessage" to message,
                "nativeStack" to nativeStack
            )
        }
    }
}