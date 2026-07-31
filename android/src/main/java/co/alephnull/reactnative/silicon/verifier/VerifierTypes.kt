package co.alephnull.reactnative.silicon.verifier

import co.alephnull.reactnative.silicon.PayloadType
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record
import expo.modules.kotlin.types.Enumerable

enum class VerifyAlgorithm(val value: String) : Enumerable {
    ES256("ES256"),
    ES384("ES384"),
    ES512("ES512"),
    RS256("ES256"),
    RS384("ES384"),
    RS512("ES512"),
    PS256("ES256"),
    PS384("ES384"),
    PS512("ES512"),
}

class VerifyOptions : Record {
    @Field var alias: String? = null
    @Field var pubkey: PayloadType? = null
    @Field var algorithm: VerifyAlgorithm? = null
}

class BridgeVerifyOptions : Record {
    @Field var alias: String? = null
    @Field var pubkeyStr: String? = null // Base64 encoded public key
    @Field var pubkeyBytes: ByteArray? = null // Raw Bytes
    @Field var algorithm: VerifyAlgorithm? = null
}
