
/**
 * Checks if a value is a POJO
 * @param value 
 * @returns 
 */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * A type-safe wrapper for Object.hasOwn
 */
export function hasOwn<T extends object, K extends PropertyKey>(
    obj: T,
    key: K
): obj is T & Record<K, unknown> {
    return Object.hasOwn(obj, key);
}

/**
 * A factory to create a type-safe guard that checks if a ReadonlySet
 * has a value.
 * 
 * @template T - The type that the Set contains
 * @template P - The param type. This can be set to make the 'value' param type-safe (i.e. if set to 'string').
 * If left as default, 'value' will be of type 'unknown'
 * @param set The Set (can be ReadonlySet or Set)
 * @returns the guard function
 */
export function createInSetGuard<T, P = unknown>(set: ReadonlySet<T>) {
    return (value: P): value is T & P => set.has(value as unknown as T);
}
