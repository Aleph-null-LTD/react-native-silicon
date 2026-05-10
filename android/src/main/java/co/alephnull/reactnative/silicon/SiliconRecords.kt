package co.alephnull.reactnative.silicon

import expo.modules.kotlin.records.Record
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.types.Enumerable

// We use Expo's 'Enumerable' interface so we can map custom lowercase JS strings
// to uppercase Kotlin enums if we want to.
enum class KeyAlgorithm(val value: String) : Enumerable {
    ES256("ES256"),
}

enum class KeyPurpose(val value: String) : Enumerable {
    SIGN("sign"),
    VERIFY("verify"),
    ENCRYPT("encrypt"),
    DECRYPT("decrypt")
}

class GenerateKeyOptions : Record {
    @Field lateinit var alias: String
    @Field var algorithm: KeyAlgorithm = KeyAlgorithm.ES256
    @Field lateinit var purposes: List<KeyPurpose>
    @Field val useStrongBox: Boolean = false
    @Field val requireStrongBox: Boolean = false
    @Field val requireUserAuth: Boolean = false
    @Field val invalidateUserAuthOnChange: Boolean = false
}