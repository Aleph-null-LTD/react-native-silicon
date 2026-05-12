package co.alephnull.reactnative.silicon.signer

import co.alephnull.reactnative.silicon.keystoremanager.AndroidOptions
import co.alephnull.reactnative.silicon.keystoremanager.KeyPurpose
import co.alephnull.reactnative.silicon.keystoremanager.UserAuthOptions
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

class SignOptions : Record {
    @Field lateinit var encoding: SignEncoding
    @Field lateinit var algorithm: SignAlgorithm
}