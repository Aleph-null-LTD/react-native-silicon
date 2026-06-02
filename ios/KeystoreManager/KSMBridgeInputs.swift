import ExpoModulesCore

// Set to Codable for KeyMetadata
enum KeyPurpose: String, Enumerable, Codable {
    case SIGN = "SIGN"
    case VERIFY = "VERIFY"
    case ENCRYPT = "ENCRYPT"
    case DECRYPT = "DECRYPT"
    case WRAP = "WRAP"
    case AGREE = "AGREE"
}

// Set to Codable for KeyMetadata
enum AuthPolicy: String, Enumerable, Codable {
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
    case B64URL = "B64URL"
}

enum KeyAlgorithm: String, Enumerable {
    case EC_P256 = "EC_P256"
    case EC_P384 = "EC_P384"
    case EC_P521 = "EC_P521"
    case RSA_2048 = "RSA_2048"
    case RSA_3072 = "RSA_3072"
    case RSA_4096 = "RSA_4096"
}

enum HardwarePolicy: String, Enumerable {
    case REQUIRE_SECURE_ENCLAVE = "REQUIRE_SECURE_ENCLAVE"
    case PREFER_SECURE_ENCLAVE = "PREFER_SECURE_ENCLAVE"
    case SOFTWARE_ONLY = "SOFTWARE_ONLY"
}

// Set to Codable for KeyMetadata
enum KeyDigests: String, Enumerable, Codable {
    case SHA256 = "SHA256"
    case SHA384 = "SHA384"
    case SHA512 = "SHA512"
}

// Set to Codable for KeyMetadata
enum SignaturePaddingAlgorithm: String, Enumerable, Codable {
    case PKCS1 = "PKCS1"
    case PSS = "PSS"
}

struct IosOptions: Record {
    @Field
    var algorithm: KeyAlgorithm = .EC_P256
    
    @Field
    var digests: [KeyDigests]? = nil
    
    @Field
    var signaturePaddingAlgorithm: SignaturePaddingAlgorithm? = nil
    
    @Field
    var hardwarePolicy: HardwarePolicy = .REQUIRE_SECURE_ENCLAVE
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
