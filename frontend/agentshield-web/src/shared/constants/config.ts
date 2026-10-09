/** Runtime configuration derived from Vite environment variables (public — never secrets). */
export const apiConfig = {
  baseUrl: import.meta.env.VITE_API_BASE_URL ?? '',
  timeoutMs: 15_000,
} as const
