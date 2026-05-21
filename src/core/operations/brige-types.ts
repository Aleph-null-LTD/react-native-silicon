import { VerifyAlgorithms } from "./types"

/**
 * Options that will be passed to the Native bridge
 */
export type BridgeVerifyOpts = {
    alias: string | undefined,
    pubkeyB64: string | undefined,
    algorithm: VerifyAlgorithms
}
