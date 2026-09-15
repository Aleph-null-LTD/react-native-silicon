package co.alephnull.reactnative.silicon

import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record

class BridgePayloadRecord : Record {
    @Field var text: String? = null
    @Field var bytes: ByteArray? = null
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
        text != null -> PayloadText(text as String)
        bytes != null -> PayloadByteArr(bytes as ByteArray)
        else -> throw IllegalArgumentException("Payload record must contain either 'text' or 'bytes'.")
    }
}
