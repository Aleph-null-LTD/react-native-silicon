package co.alephnull.reactnative.silicon.randomgen

import expo.modules.kotlin.types.Enumerable

enum class RandomBytesFormat (val value: String) : Enumerable {
    B64URL("B64URL"),
    B64("B64"),
    BYTES("BYTES")
}
