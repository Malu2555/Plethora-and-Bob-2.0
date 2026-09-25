<script setup>
/**
 * Public registration page bound to POST /api/v1/auth/register.
 * Success (201 + JWT pair) signs the new account in immediately and the
 * router continues to ?redirect=… or the dashboard. 409/422/429 are rendered
 * inline rather than toasted by the api interceptor.
 */
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { extractDetail } from '../services/api'
import { useAuthStore } from '../stores/auth'
import logger from '../utils/logger'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

const form = reactive({ username: '', email: '', password: '', confirm: '' })
const errorMessage = ref('')

async function submit() {
  errorMessage.value = ''
  const username = form.username.trim()
  const email = form.email.trim()
  if (!username || !email || !form.password) {
    errorMessage.value = 'All fields are required.'
    return
  }
  if (username.length < 3) {
    errorMessage.value = 'Username must be at least 3 characters.'
    return
  }
  if (form.password.length < 8) {
    errorMessage.value = 'Password must be at least 8 characters.'
    return
  }
  if (form.password !== form.confirm) {
    errorMessage.value = 'Passwords do not match.'
    return
  }
  try {
    await auth.register({ username, email, password: form.password })
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : null
    await router.push(redirect || { name: 'dashboard' })
  } catch (err) {
    const status = err?.response?.status
    logger.warn('register', 'sign-up failed', status)
    errorMessage.value =
      status === 409
        ? 'Account already exists — try signing in instead.'
        : status === 429
          ? 'Too many attempts — wait a moment and retry.'
          : extractDetail(err?.response, 'Registration failed. Is the backend running?')
  }
}
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-slate-950 p-4">
    <div class="card w-full max-w-sm space-y-5">
      <div class="flex flex-col items-center gap-2 text-center">
        <span class="flex h-14 w-14 items-center justify-center rounded-2xl bg-cyan-500/15 text-3xl">🛡</span>
        <h1 class="text-lg font-semibold text-slate-100">Create your account</h1>
        <p class="text-xs text-slate-500">Sentinel Monitor · self-service sign-up</p>
      </div>

      <form class="space-y-3" @submit.prevent="submit">
        <div class="space-y-1">
          <label for="username" class="label">Username</label>
          <input id="username" v-model="form.username" class="input w-full" autocomplete="username" autofocus />
        </div>
        <div class="space-y-1">
          <label for="email" class="label">Email</label>
          <input id="email" v-model="form.email" type="email" class="input w-full" autocomplete="email" />
        </div>
        <div class="space-y-1">
          <label for="password" class="label">Password</label>
          <input id="password" v-model="form.password" type="password" class="input w-full" autocomplete="new-password" />
        </div>
        <div class="space-y-1">
          <label for="confirm" class="label">Confirm password</label>
          <input id="confirm" v-model="form.confirm" type="password" class="input w-full" autocomplete="new-password" />
        </div>

        <p v-if="errorMessage" class="rounded-lg border border-red-700 bg-red-950/60 px-3 py-2 text-sm text-red-200">
          {{ errorMessage }}
        </p>

        <button type="submit" class="btn-primary w-full" :disabled="auth.busy">
          {{ auth.busy ? 'Creating account…' : 'Create account' }}
        </button>

        <p class="text-center text-xs text-slate-500">
          Already have an account?
          <button
            type="button"
            class="font-medium text-cyan-400 hover:text-cyan-300"
            @click="router.push({ name: 'login' })"
          >
            Sign in
          </button>
        </p>
      </form>
    </div>
  </div>
</template>
