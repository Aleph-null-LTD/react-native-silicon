import ExpoModulesCore

enum VerifyAlgorithms: String, Enumerable {
    case ES256 = "ES256"
    case ES384 = "ES384"
    case ES512 = "ES512"
    case RS256 = "RS256"
    case RS384 = "RS384"
    case RS512 = "RS512"
    case PS256 = "PS256"
    case PS384 = "PS384"
    case PS512 = "PS512"
}

struct VerifyOptions: Record {
    @Field
    var alias: String? = nil
    
    @Field
    var pubkey: String? = nil
    
    @Field
    var algorithm: VerifyAlgorithms?
}
