/**
 * Axios singleton + interceptors for the Sentinel backend.
 *
 *   request : attaches `Authorization: Bearer <access>` (auth routes avoided)
 *   response:
 *     401  -> single-flight silent refresh -> retry the request once; if the
 *             refresh also fails the session is cleared and the user is sent
 *             back to /login
 *     429  -> toast + surface the Retry-After hint
 *     4xx  -> toast a human-readable message (422 detail mapped to strings)
 *     5xx  -> generic server error toast
 *
 * Tokens are read/written through utils/session (localStorage), never through
 * the Pinia store — this keeps the api/store dependency graph acyclic.
 */
import axios from 'axios'

import logger from '../utils/logger'
import { clearTokens, getAccessToken, getRefreshToken, setAccessToken } from '../utils/session'
import toast from '../utils/toast'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

const isAuthRoute = (url = '') =>
  url.includes('/auth/token') || url.includes('/auth/refresh') || url.includes('/auth/register')

/** Single-flight guard: concurrent 401s share one refresh request. */
let refreshPromise = null

function dropSessionAndSendHome() {
  clearTokens()
  logger.warn('api', 'session cleared after failed token refresh')
  if (window.location.pathname !== '/login') {
    window.location.assign('/login')
  }
}

api.interceptors.request.use((config) => {
  const token = getAccessToken()
  if (token && !isAuthRoute(config.url)) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export function extractDetail(response, fallback) {
  const detail = response?.data?.detail
  if (Array.isArray(detail) && detail.length) {
    return detail.map((err) => err.msg ?? String(err)).join('; ')
  }
  if (typeof detail === 'string' && detail) return detail
  if (typeof response?.data?.message === 'string') return response.data.message
  return fallback
}

async function refreshAccess() {
  const refresh = getRefreshToken()
  if (!refresh) throw new Error('no refresh token')
  const { data } = await api.post('/api/v1/auth/refresh', { refresh })
  setAccessToken(data.access)
  return data.access
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const { config, response } = error
    const status = response?.status

    // --- 401: one silent refresh, then retry the failed request once -----
    if (status === 401 && config && !config._retried && !isAuthRoute(config.url)) {
      config._retried = true
      try {
        refreshPromise = refreshPromise ?? refreshAccess()
        const fresh = await refreshPromise
        config.headers.Authorization = `Bearer ${fresh}`
        return api(config)
      } catch (refreshError) {
        logger.warn('api', 'token refresh failed', refreshError)
        dropSessionAndSendHome()
        toast('Session expired — please sign in again.', 'warning')
        throw refreshError
      } finally {
        refreshPromise = null
      }
    }

    // --- human-readable toasts ------------------------------------------
    if (status === 429) {
      const retryAfter = response.headers?.['retry-after']
      toast(`Rate limited${retryAfter ? ` — retry in ${retryAfter}s` : ''}.`, 'warning')
    } else if (status === 401 && isAuthRoute(config?.url)) {
      // Login/refresh failures are rendered inline by the forms.
    } else if (status >= 400 && status < 500) {
      toast(extractDetail(response, `Request failed (${status}).`), 'error')
    } else if (status >= 500) {
      toast('Server error — check backend logs.', 'error')
    } else if (!response) {
      toast('Network error — is the backend running?', 'error')
    }

    return Promise.reject(error)
  },
)

export default api
