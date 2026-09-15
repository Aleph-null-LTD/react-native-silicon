import { describe, expect } from "vitest";
import { test } from "@fast-check/vitest";
import fc from 'fast-check';
import { objectToBase64Url } from "../encoding";

describe('objectToBase64Url()', () => {
    const Base64UrlRegex = /^(?:[A-Za-z0-9\-_]{4})*(?:[A-Za-z0-9\-_]{2,3})?$/;

    test.prop(
        [fc.object()],
        { numRuns: 10000 }
    )('Should return valid Base64Url when obj is an object', (validObj) => {
        expect(objectToBase64Url(validObj)).matches(Base64UrlRegex);
    });
});