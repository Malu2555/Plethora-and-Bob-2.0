/**
 * Minimal JWT payload decoding (base64url + JSON) for DISPLAY claims only.
 *
 * The backend remains the only party that ever verifies a signature — the
 * client never grants access based on these values.
 */
export function decodePayload(token) {
  if (!token) return null
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')
    return JSON.parse(atob(padded))
  } catch {
    return null
  }
}

/**
 * Username claim (used to greet the operator), or null when unavailable.
 */
export function usernameFromToken(token) {
  const payload = decodePayload(token)
  if (!payload) return null
  return payload.username ?? payload.user__username ?? null
}
