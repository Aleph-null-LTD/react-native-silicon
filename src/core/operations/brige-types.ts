import { VerifyAlgorithms } from "./types"

/**
 * Options that will be passed to the Native bridge
 */
export type BridgeVerifyOpts = {
    alias: string | undefined,
    algorithm: VerifyAlgorithms | undefined
}

