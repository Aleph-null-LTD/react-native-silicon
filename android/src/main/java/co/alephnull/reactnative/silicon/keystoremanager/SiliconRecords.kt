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
    SIGN("SIGN"),
    VERIFY("VERIFY"),
    ENCRYPT("ENCRYPT"),
    DECRYPT("DECRYPT"),
    WRAP("WRAP"),
    AGREE("AGREE"),
    ATTEST("ATTEST")
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
    @Field var algorithm: KeyAlgorithm = KeyAlgorithm.ES256
    @Field lateinit var digests: List<KeyDigest>
    @Field var hardwarePolicy: HardwarePolicy = HardwarePolicy.PREFER_STRONGBOX
}

enum class AuthPolicy(val value: String) : Enumerable {
    BIOMETRICS_ONLY("BIOMETRICS_ONLY"),
    BIOMETRICS_OR_CREDENTIAL("BIOMETRICS_OR_CREDENTIAL")
}

class UserAuthOptions : Record {
    @Field var require: Boolean = false
    @Field var timeout: Int = 0
    @Field var invalidateOnEnrollment: Boolean = true
    @Field var policy: AuthPolicy = AuthPolicy.BIOMETRICS_ONLY
}

enum class PubkeyFormat(val value: String) : Enumerable {
    PEM("PEM"),
    B64("B64")
}

class GenerateKeyOptions : Record {
    @Field var purposes: List<KeyPurpose> = listOf(KeyPurpose.SIGN, KeyPurpose.VERIFY)
    @Field var userAuth: UserAuthOptions = UserAuthOptions()
    @Field var attestChallenge: String? = null
    @Field var pubkeyFormat: PubkeyFormat = PubkeyFormat.PEM
    @Field var android: AndroidOptions = AndroidOptions()
}