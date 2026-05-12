package co.alephnull.reactnative.silicon

import expo.modules.kotlin.exception.CodedException

open class SiliconException(
    code: String,
    message: String,
    cause: Throwable? = null
) : CodedException(code, message, cause)
