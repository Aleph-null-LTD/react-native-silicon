import ExpoModulesCore

enum KeyPurpose: String, Enumerable {
    case SIGN = "SIGN"
    case VERIFY = "VERIFY"
    case ENCRYPT = "ENCRYPT"
    case DECRYPT = "DECRYPT"
    case WRAP = "WRAP"
    case AGREE = "AGREE"
}

enum AuthPolicy: String, Enumerable {
    case BIOMETRICS_ONLY = "BIOMETRICS_ONLY"
    case BIOMETRICS_OR_CREDENTIAL = "BIOMETRICS_OR_CREDENTIAL"
}

struct UserAuthOptions: Record {
    @Field
    var require: Bool = false
    
    @Field
    var timeout: Int = 0
    
    @Field
    var invalidateOnEnrollment: Bool = true
    
    @Field
    var policy: AuthPolicy = .BIOMETRICS_ONLY
}

enum PubKeyFormat: String, Enumerable {
    case PEM = "PEM"
    case B64 = "B64"
}

enum KeyAlgorithm: String, Enumerable {
    case ES256 = "ES256"
}

enum HardwarePolicy: String, Enumerable {
    case REQUIRE_SECURE_ENCLAVE = "REQUIRE_SECURE_ENCLAVE"
    case PREFER_SECURE_ENCLAVE = "PREFER_SECURE_ENCLAVE"
    case SOFTWARE_ONLY = "SOFTWARE_ONLY"
}

struct IosOptions: Record {
    @Field
    var algorithm: KeyAlgorithm = .ES256
    
    @Field
    var hardwarePolicy: HardwarePolicy = .PREFER_SECURE_ENCLAVE
}

struct GenerateKeyOptions: Record {
    @Field
    var purposes: [KeyPurpose] = [.SIGN, .VERIFY]
    
    @Field
    var userAuth: UserAuthOptions = UserAuthOptions()
    
    @Field
    var attestChallenge: String? = nil
    
    @Field
    var pubkeyFormat: PubKeyFormat = .PEM
    
    @Field
    var ios: IosOptions = IosOptions()
}
