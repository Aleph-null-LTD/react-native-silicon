import ExpoModulesCore

enum SignEncoding: String, Enumerable {
    case BYTES = "BYTES"
    case B64 = "B64"
    case B64URL = "B64URL"
}

enum SignFormat: String, Enumerable {
    case P1363 = "P1363"
    case DER = "DER"
}

struct SignOptions: Record {
    @Field
    var encoding: SignEncoding = .BYTES
    
    @Field
    var digest: KeyDigests? = nil
    
    @Field
    var format: SignFormat = .P1363
}
