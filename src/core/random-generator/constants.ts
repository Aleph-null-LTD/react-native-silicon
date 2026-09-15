import { createInSetGuard } from "../../utils/validation";

export const randomBytesFormats = {
    B64URL: 'B64URL',
    B64: 'B64',
    BYTES: 'BYTES'
} as const

const randomBytesFormatSet: ReadonlySet<keyof typeof randomBytesFormats> = new Set(Object.values(randomBytesFormats));

export const isRandomBytesFormat = createInSetGuard(randomBytesFormatSet);
