// Reexport the native module. On web, it will be resolved to ReactNativeSiliconModule.web.ts
// and on native platforms to ReactNativeSiliconModule.ts
export { default } from './module';
export * from  './types';

export * from './core/device';
export * from './core/keys/keys';
export * from './core/operations';
export * from './core/random';
export * from './identity/dpop';
export * from './identity/jwk';
export * from './identity/jwt';

export * from './errors';

export function GetSiliconStatus() {
    return 'This lib is a WIP';
}