package co.alephnull.reactnative.silicon.keystoremanager

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

enum class KeyDigest(val value: String) : Enumerable {
    SHA256("SHA256")
}

enum class HardwarePolicy(val value: String) : Enumerable {
    REQUIRE_STRONGBOX("REQUIRE_STRONGBOX"),
    PREFER_STRONGBOX("PREFER_STRONGBOX"),
    USE_TEE("USE_TEE")
}

class AndroidOptions : Record {
    @Field val algorithm: KeyAlgorithm = KeyAlgorithm.ES256
    @Field lateinit var digests: List<KeyDigest>
    @Field val hardwarePolicy: HardwarePolicy = HardwarePolicy.PREFER_STRONGBOX
}

class GenerateKeyOptions : Record {
    @Field lateinit var purposes: List<KeyPurpose>
    @Field lateinit var android: AndroidOptions
    @Field val requireUserAuth: Boolean = false
    @Field val invalidateUserAuthOnChange: Boolean = false
}