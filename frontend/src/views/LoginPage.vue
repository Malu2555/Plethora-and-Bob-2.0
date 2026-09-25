<script setup>
/**
 * Public login page bound to POST /api/v1/auth/token.
 * On success the router continues to ?redirect=… or the dashboard. 401s are
 * rendered inline (the api interceptor deliberately does not toast them).
 */
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { useAuthStore } from '../stores/auth'
import logger from '../utils/logger'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

const form = reactive({ username: '', password: '' })
const errorMessage = ref('')

async function submit() {
  errorMessage.value = ''
  if (!form.username.trim() || !form.password) {
    errorMessage.value = 'Username and password are required.'
    return
  }
  try {
    await auth.login({ username: form.username.trim(), password: form.password })
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : null
    await router.push(redirect || { name: 'dashboard' })
  } catch (err) {
    logger.warn('login', 'sign-in failed', err?.response?.status)
    errorMessage.value =
      err?.response?.status === 401
        ? 'Invalid credentials — please try again.'
        : err?.response?.status === 429
          ? 'Too many attempts — wait a moment and retry.'
          : 'Sign-in failed. Is the backend running?'
  }
}
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-slate-950 p-4">
    <div class="card w-full max-w-sm space-y-5">
      <div class="flex flex-col items-center gap-2 text-center">
        <span class="flex h-14 w-14 items-center justify-center rounded-2xl bg-cyan-500/15 text-3xl">🛡</span>
        <h1 class="text-lg font-semibold text-slate-100">Sentinel Monitor</h1>
        <p class="text-xs text-slate-500">Security posture · vault · audit telemetry</p>
      </div>

      <form class="space-y-3" @submit.prevent="submit">
        <div class="space-y-1">
          <label for="username" class="label">Username</label>
          <input id="username" v-model="form.username" class="input w-full" autocomplete="username" autofocus />
        </div>
        <div class="space-y-1">
          <label for="password" class="label">Password</label>
          <input id="password" v-model="form.password" type="password" class="input w-full" autocomplete="current-password" />
        </div>

        <p v-if="errorMessage" class="rounded-lg border border-red-700 bg-red-950/60 px-3 py-2 text-sm text-red-200">
          {{ errorMessage }}
        </p>

        <button type="submit" class="btn-primary w-full" :disabled="auth.busy">
          {{ auth.busy ? 'Signing in…' : 'Sign in' }}
        </button>

        <p class="text-center text-xs text-slate-500">
          Need an account?
          <button
            type="button"
            class="font-medium text-cyan-400 hover:text-cyan-300"
            @click="router.push({ name: 'register' })"
          >
            Register
          </button>
        </p>
      </form>
    </div>
  </div>
</template>