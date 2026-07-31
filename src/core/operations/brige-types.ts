import { VerifyAlgorithms } from "./types"

/**
 * Options that will be passed to the Native bridge
 */
export type BridgeVerifyOpts = {
    alias: string | undefined,
    pubkeyStr: string | undefined,
    pubkeyBytes: Uint8Array | undefined,
    algorithm: VerifyAlgorithms | undefined
}

