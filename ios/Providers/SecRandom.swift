
protocol SecRandomProvider {
    func copyBytes(
        _ rnd: SecRandomRef?,
        _ count: Int,
        _ bytes: UnsafeMutableRawPointer
    ) -> Int32
}

struct SecRandom: SecRandomProvider {
    func copyBytes(
        _ rnd: SecRandomRef?,
        _ count: Int,
        _ bytes: UnsafeMutableRawPointer
    ) -> Int32 {
        return SecRandomCopyBytes(rnd, count, bytes)
    }
}
