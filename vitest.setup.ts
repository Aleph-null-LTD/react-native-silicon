import { vi } from 'vitest';

// Mock Expo modules
vi.mock(
    'expo',
    () => {
        return {
            // Replicate the Native Module proxy system
            requireNativeModule: vi.fn(
                () => ({
                    getCapabilities: vi.fn(),
                    generateKey: vi.fn(),
                    deleteKey: vi.fn(),
                    deleteAllKeys: vi.fn(),
                    keyExists: vi.fn(),
                    listKeys: vi.fn(),
                    getPubKey: vi.fn(),
                    attestKey: vi.fn(),
                    getKeyInfo: vi.fn(),
                    validateKey: vi.fn(),
                    sign: vi.fn(),
                    verify: vi.fn(),
                    generateSecureRandomBytes: vi.fn(),
                    getJwk: vi.fn()
                })
            ),

            // Replicate the base NativeModule because we extend it in module.ts
            NativeModule: class {}
        };
    }
);
