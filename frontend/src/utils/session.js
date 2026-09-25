/**
 * Access to the JWT pair persisted by the auth flow.
 *
 * localStorage is the single source of truth so both the axios interceptor
 * and the Pinia auth store stay in sync WITHOUT importing each other
 * (which would create a module cycle). Refresh-token rotation updates are
 * written back through setTokens/setAccessToken.
 */
const ACCESS_KEY = 'sentinel.access'
const REFRESH_KEY = 'sentinel.refresh'

export function getAccessToken() {
  return localStorage.getItem(ACCESS_KEY) || null
}

export function getRefreshToken() {
  return localStorage.getItem(REFRESH_KEY) || null
}

export function setTokens(access, refresh) {
  localStorage.setItem(ACCESS_KEY, access)
  localStorage.setItem(REFRESH_KEY, refresh)
}

export function setAccessToken(access) {
  localStorage.setItem(ACCESS_KEY, access)
}

export function clearTokens() {
  localStorage.removeItem(ACCESS_KEY)
  localStorage.removeItem(REFRESH_KEY)
}
