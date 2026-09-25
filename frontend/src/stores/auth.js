/**
 * Pinia store for the auth session.
 *
 * Token persistence lives in utils/session (localStorage); this store only
 * tracks the display username and orchestrates login/logout. Keeping the
 * token OUT of Pinia state means the axios interceptor can read/write it
 * without a store import — no circular dependency.
 */
import { defineStore } from 'pinia'

import api from '../services/api'
import { usernameFromToken } from '../utils/jwt'
import logger from '../utils/logger'
import { clearTokens, getAccessToken, setTokens } from '../utils/session'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    /** Display username decoded from the JWT (survives page reloads). */
    user: usernameFromToken(getAccessToken()),
    /** True while a login request is in flight (disables the form). */
    busy: false,
  }),

  getters: {
    isAuthenticated: () => Boolean(getAccessToken()),
  },

  actions: {
    async login(credentials) {
      this.busy = true
      try {
        const { data } = await api.post('/api/v1/auth/token', credentials)
        setTokens(data.access, data.refresh)
        this.user = usernameFromToken(data.access)
        logger.info('auth', `login ok user=${this.user}`)
        return this.user
      } finally {
        this.busy = false
      }
    },

    async register(payload) {
      this.busy = true
      try {
        const { data } = await api.post('/api/v1/auth/register', payload)
        setTokens(data.access, data.refresh)
        this.user = data.username
        logger.info('auth', `register ok user=${this.user}`)
        return this.user
      } finally {
        this.busy = false
      }
    },

    logout() {
      clearTokens()
      this.user = null
      logger.info('auth', 'logout')
    },
  },
})
