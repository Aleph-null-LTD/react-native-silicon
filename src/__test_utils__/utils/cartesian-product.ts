export type CartesianProduct<T extends readonly (readonly unknown[])[]> = {
  -readonly [K in keyof T]: T[K][number];
};

/**
 * Generates all combinations (cartesian product) of the elements in the given arbitrary arrays.
 * @param arrays 
 * @returns An array of all the combinations of the values from the given arrays
 */
export function cartesianProduct<const T extends readonly (readonly unknown[])[]>(
  ...arrays: T
): CartesianProduct<T>[] {
  return arrays.reduce<unknown[][]>(
    (acc, curr) => acc.flatMap((c) => curr.map((n) => [...c, n])),
    [[]]
  ) as CartesianProduct<T>[];
}
