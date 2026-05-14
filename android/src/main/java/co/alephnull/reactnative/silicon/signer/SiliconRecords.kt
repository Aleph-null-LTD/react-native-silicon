package co.alephnull.reactnative.silicon.signer

import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record
import expo.modules.kotlin.types.Enumerable

enum class SignEncoding(val value: String) : Enumerable {
    B64("B64"),
    B64_URL("B64_URL")
}

enum class SignAlgorithm(val value: String) : Enumerable {
    SHA256("SHA256")
}

enum class SignFormat(val value: String) : Enumerable {
    P1363("P1363"),
    DER("DER")
}

class SignOptions : Record {
    @Field var encoding: SignEncoding = SignEncoding.B64_URL
    @Field var algorithm: SignAlgorithm = SignAlgorithm.SHA256
    @Field var format: SignFormat = SignFormat.P1363
}