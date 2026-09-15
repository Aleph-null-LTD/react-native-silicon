
protocol SecAccessControlsProvider {
    func createWithFlags(
        _ allocator: CFAllocator?,
        _ protection: CFTypeRef,
        _ flags: SecAccessControlCreateFlags,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> SecAccessControl?
}

struct SecAccessControls: SecAccessControlsProvider {
    func createWithFlags(
        _ allocator: CFAllocator?,
        _ protection: CFTypeRef,
        _ flags: SecAccessControlCreateFlags,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> SecAccessControl? {
        return SecAccessControlCreateWithFlags(allocator, protection, flags, error)
    }
}
