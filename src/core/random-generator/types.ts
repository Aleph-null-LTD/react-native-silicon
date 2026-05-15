import { randomBytesFormats } from "./constants";

export type RandomBytesFormat = keyof typeof randomBytesFormats;

export interface RandomGenFormatTypeMap {
    [randomBytesFormats.B64URL]: string,
    [randomBytesFormats.B64]: string,
    [randomBytesFormats.BYTES]: Uint8Array
}
