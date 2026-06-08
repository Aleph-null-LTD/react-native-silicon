package co.alephnull.reactnative.silicon.keystoremanager

import expo.modules.kotlin.records.Record
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.types.Enumerable

// We use Expo's 'Enumerable' interface so we can map custom lowercase JS strings
// to uppercase Kotlin enums if we want to.
enum class KeyAlgorithm(val value: String) : Enumerable {
    EC_P256("EC_P256"),
    EC_P384("EC_P384"),
    EC_P521("EC_P521"),
    RSA_2048("RSA_2048"),
    RSA_3072("RSA_3072"),
    RSA_4096("RSA_4096")
}

enum class KeyPurpose(val value: String) : Enumerable {
    SIGN("SIGN"),
    VERIFY("VERIFY"),
    ENCRYPT("ENCRYPT"),
    DECRYPT("DECRYPT"),
    WRAP("WRAP"),
    AGREE("AGREE"),
    //ATTEST("ATTEST") // NOTE: ATTEST has been removed to keep the API symmetric between platforms
}

enum class KeyDigest(val value: String) : Enumerable {
    SHA256("SHA256"),
    SHA384("SHA384"),
    SHA512("SHA512")
}

enum class SignaturePaddingAlgorithm(val value: String) : Enumerable {
    PKCS1("PKCS1"),
    PSS("PSS")
}

enum class HardwarePolicy(val value: String) : Enumerable {
    REQUIRE_STRONGBOX("REQUIRE_STRONGBOX"),
    PREFER_STRONGBOX("PREFER_STRONGBOX"),
    PREFER_STRONGBOX_ALLOW_SOFTWARE("PREFER_STRONGBOX_ALLOW_SOFTWARE"),
    REQUIRE_TEE("REQUIRE_TEE"),
    PREFER_TEE_ALLOW_SOFTWARE("PREFER_TEE_ALLOW_SOFTWARE"),
    SOFTWARE_ONLY("SOFTWARE_ONLY")
}

class AndroidOptions : Record {
    @Field var algorithm: KeyAlgorithm = KeyAlgorithm.EC_P256
    @Field var digests: List<KeyDigest>? = null
    @Field var signaturePaddingAlgorithm: SignaturePaddingAlgorithm = SignaturePaddingAlgorithm.PSS
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
    B64("B64"),
    B64URL("B64URL"),
    SPKI("SPKI")
}

class GenerateKeyOptions : Record {
    @Field var purposes: List<KeyPurpose> = listOf(KeyPurpose.SIGN, KeyPurpose.VERIFY)
    @Field var userAuth: UserAuthOptions = UserAuthOptions()
    @Field var attestChallenge: ByteArray? = null
    @Field var android: AndroidOptions = AndroidOptions()
}
