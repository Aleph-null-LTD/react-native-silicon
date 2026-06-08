package co.alephnull.reactnative.silicon

import expo.modules.kotlin.types.Enumerable

enum class SiliconErrorCode(val value: String) {
    INTERNAL_ERROR("INTERNAL_ERROR"),
    INVALID_ARGUMENT("INVALID_ARGUMENT"),
    UNSUPPORTED("UNSUPPORTED"),
    KEY_NOT_FOUND("KEY_NOT_FOUND"),
    KEY_POLICY_VIOLATION ("KEY_POLICY_VIOLATION"),
    INCOMPATIBLE("INCOMPATIBLE"),
    OPERATION_NOT_PERMITTED("OPERATION_NOT_PERMITTED"),
    MALFORMED_DATA("MALFORMED_DATA"),
    AUTH_CANCELED("AUTH_CANCELED"),
    AUTH_LOCKED_OUT("AUTH_LOCKED_OUT"),
    AUTH_NOT_ENROLLED("AUTH_NOT_ENROLLED"),
    KEY_INVALIDATED("KEY_INVALIDATED"),

    // Generate key errors
    GENERATE_KEY_FAILED("GENERATE_KEY_FAILED"),
    ATTEST_NOT_AVAILABLE("ATTEST_NOT_AVAILABLE"),
    ALIAS_IN_USE("ALIAS_IN_USE"),
    HARDWARE_NOT_AVAILABLE("HARDWARE_NOT_AVAILABLE"),
    STRONGBOX_NOT_SUPPORTED("STRONGBOX_NOT_SUPPORTED"),

    GET_CAPABILITIES_FAILED("GET_CAPABILITIES_FAILED"),
    DELETE_FAILED("DELETE_FAILED"),
    DELETE_ALL_FAILED("DELETE_ALL_FAILED"),
    KEY_EXISTS_FAILED("KEY_EXISTS_FAILED"),
    LIST_KEYS_FAILED("LIST_KEYS_FAILED"),
    GET_PUB_KEY_FAILED("GET_PUB_KEY_FAILED"),
    VALIDATE_KEY_FAILED("VALIDATE_KEY_FAILED"),
    ATTEST_KEY_FAILED("ATTEST_KEY_FAILED"),
    GET_KEY_INFO_FAILED("GET_KEY_INFO_FAILED"),
    GET_JWK_FAILED("GET_JWK_FAILED"),
    VERIFY_FAILED("VERIFY_FAILED"),
    RANDOM_GEN_FAILED("RANDOM_GEN_FAILED"),
    SIGN_FAILED("SIGN_FAILED")
}

/**
 * A standardized result for the Silicon bridge.
 * [T] is the type of data returned on success.
 */
sealed class SiliconResult<out T> {
    data class Success<out T>(val data: T) : SiliconResult<T>()

    data class Failure(
        val code: SiliconErrorCode,
        val message: String,
        val nativeStack: String? = null
    ) : SiliconResult<Nothing>()

    /**
     * Converts the Result into a Map that the Expo Bridge can serialize to JS.
     */
    fun toBridgeMap(): Map<String, Any?> {
        when (this) {
            is Success -> {
                return if (data == Unit || data == null) {
                    mapOf("success" to true)
                } else {
                    mapOf("success" to true, "data" to data)
                }
            }
            is Failure -> {
                val dict = mutableMapOf<String, Any>(
                    "success" to false,
                    "errorCode" to code.value,
                    "errorMessage" to "[RN-Silicon: Android] $message",
                )

                if (nativeStack != null) {
                    dict["nativeStack"] = nativeStack
                }

                return dict
            }
        }
    }
}

/**
 * Unwraps the Success value, or executes the block (which MUST return/throw) if it's a Failure.
 */
inline fun <T> SiliconResult<T>.onFailure(block: (SiliconResult.Failure) -> Nothing): T {
    return when (this) {
        is SiliconResult.Success -> this.data
        is SiliconResult.Failure -> block(this)
    }
}