import { describe, it, expect, vi } from "vitest";
import fc from 'fast-check';
import { test } from '@fast-check/vitest';
import { sign } from "../../core/operations/operations";
import { objectToBase64Url } from "../../utils/encoding";
import { signJwt } from "../jwt";
import { SiliconError, SiliconErrorCode } from "../../errors";
import { isPlainObject } from "../../utils/validation";

vi.mock("../../core/operations/operations");
vi.mock("../../utils/encoding");

describe('signJwt()', () => {
    const jwtHeader = {
        typ: "JWT",
        randomKey: 12345
    };
    const jwtPayload = {
        randomKey: 12345,
        anotherRandomKey: "some-data"
    };

    const signMockVal = 'some-random-signature';
    const b64MockVal = "c29tZS1yYW5kb20tYmFzZTY0VXJs"
    
    const expectedJwt = `${b64MockVal}.${b64MockVal}.${signMockVal}`;

    const setupMocks = () => {
        vi.mocked(objectToBase64Url).mockReturnValue(b64MockVal);
        vi.mocked(sign).mockResolvedValue(signMockVal);
    };

    it('should return successfully when all params are valid', async () => {
        setupMocks();
        
        await expect(
            signJwt('some-random-alias', jwtHeader, jwtPayload, 'SHA256')
        ).resolves.toBe(expectedJwt);

        expect(sign).toHaveBeenCalledOnce();
    });

    test.prop(
        [fc.anything()]
    )("should throw when alias is not a string, or is empty", async (chaoticData) => {
        setupMocks();

        if (typeof chaoticData == 'string' && chaoticData.trim().length > 0) {
            await expect(
                signJwt(chaoticData, jwtHeader, jwtPayload, 'SHA256')
            ).resolves.toBe(expectedJwt);

            expect(sign).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await signJwt(chaoticData, jwtHeader, jwtPayload, 'SHA256');
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected signJwt() to throw, but it did not');

            expect(sign).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything()]
    )('should throw when header is not a POJO', async (chaoticData) => {
        setupMocks();
        
        if (isPlainObject(chaoticData)) {
            await expect(signJwt('some-random-alias', chaoticData, jwtPayload, 'SHA256')).resolves.toBe(expectedJwt);
            expect(sign).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await signJwt('some-random-alias', chaoticData, jwtPayload, 'SHA256');
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected signJwt() to throw, but it did not');

            expect(sign).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [fc.anything()]
    )('should throw when payload is not a POJO', async (chaoticData) => {
        setupMocks();

        if (isPlainObject(chaoticData)) {
            await expect(signJwt('some-random-alias', jwtHeader, chaoticData, 'SHA256')).resolves.toBe(expectedJwt);
            expect(sign).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await signJwt('some-random-alias', jwtHeader, chaoticData, 'SHA256');
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected signJwt() to throw, but it did not');

            expect(sign).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });

    test.prop(
        [
            fc.oneof(
                fc.constant('SHA256'),
                fc.constant('SHA384'),
                fc.constant('SHA512'),
                fc.constant(undefined),
                fc.anything()
            )
        ]
    )('should throw when digest is defined but not a valid string literal', async (chaoticData) => {
        setupMocks();

        if (chaoticData === 'SHA256' ||
            chaoticData === 'SHA384' ||
            chaoticData === 'SHA512' ||
            chaoticData === undefined
        ) {
            await expect(signJwt('some-random-alias', jwtHeader, jwtPayload, chaoticData)).resolves.toBe(expectedJwt);
            expect(sign).toHaveBeenCalledOnce();

        } else {
            let didThrow = true;
            try {
                // @ts-expect-error
                await signJwt('some-random-alias', jwtHeader, jwtPayload, chaoticData);
                didThrow = false;
            } catch (error) {
                expect(error).toBeInstanceOf(SiliconError);
            }

            if (!didThrow) expect.fail('expected signJwt() to throw, but it did not');

            expect(sign).toHaveBeenCalledTimes(0);
        }

        vi.clearAllMocks();
    });
});
