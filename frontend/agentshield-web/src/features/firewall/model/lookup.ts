/**
 * The table's own entry for `key`, or `undefined`. A plain `table[key]` would also find inherited members for keys
 * such as `constructor` or `__proto__`; API values are untrusted, so presentation lookups never use it.
 */
export function ownEntry<T>(table: Readonly<Record<string, T>>, key: string): T | undefined {
  return Object.hasOwn(table, key) ? table[key] : undefined
}
