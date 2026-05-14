package co.alephnull.reactnative.silicon

import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record

class BridgePayloadRecord : Record {
    @Field val text: String? = null
    @Field val bytes: ByteArray? = null
}

sealed interface PayloadType
@JvmInline
value class PayloadText(val text: String) : PayloadType
@JvmInline
value class PayloadByteArr(val arr: ByteArray) : PayloadType

/**
 * Extension function to safely cross from BridgePayloadRecord to PayloadType
 */
fun BridgePayloadRecord.toPayloadType(): PayloadType {
    return when {
        text != null -> PayloadText(text)
        bytes != null -> PayloadByteArr(bytes)
        else -> throw IllegalArgumentException("Payload record must contain either 'text' or 'bytes'.")
    }
}
