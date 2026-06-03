import ExpoModulesCore

struct BridgePayloadRecord: Record {
    @Field var text: String?
    @Field var bytes: Data? // Expo maps JS Uint8Array to Swift Data
}

enum PayloadType {
    case text(String)
    case byteArr(Data)
}

extension BridgePayloadRecord {
    func toPayloadType() throws -> PayloadType {
        if let text = self.text {
            return .text(text)
        } else if let bytes = self.bytes {
            return .byteArr(bytes)
        } else {
            throw NSError(
                domain: "Silicon",
                code: 0,
                userInfo: [NSLocalizedDescriptionKey: "Payload record must contain either text or bytes."]
            )
        }
    }
}
