<style scoped>
.nav-active {
  background-color: rgba(8, 145, 178, 0.12);
  color: #67e8f9;
}
</style>

<script setup>
/**
 * Authenticated layout: left navigation + user chip, content via router-view.
 */
import { computed } from 'vue'
import { useRouter } from 'vue-router'

import { useAuthStore } from '../stores/auth'
import logger from '../utils/logger'

const auth = useAuthStore()
const router = useRouter()

const NAV = [
  { name: 'dashboard', path: '/', label: 'Dashboard', icon: 'M3 12l9-9 9 9M5 10v10h5v-6h4v6h5V10' },
  { name: 'vault', path: '/vault', label: 'Vault', icon: 'M12 3l8 4v5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V7l8-4z' },
  { name: 'security', path: '/security', label: 'Findings', icon: 'M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z' },
  { name: 'audit', path: '/audit', label: 'Audit Log', icon: 'M4 6h16M4 12h10M4 18h7' },
]

const displayUser = computed(() => auth.user || 'operator')
const initial = computed(() => displayUser.value.charAt(0).toUpperCase())

function signOut() {
  auth.logout()
  logger.info('shell', 'user signed out')
  router.push({ name: 'login' })
}
</script>

<template>
  <div class="flex h-screen flex-col bg-slate-950 text-slate-200 md:flex-row">
    <aside class="flex shrink-0 flex-row items-center justify-between gap-4 border-b border-slate-800 bg-slate-900 px-4 py-3 md:h-full md:w-60 md:flex-col md:items-stretch md:justify-start md:border-b-0 md:border-r md:px-3 md:py-6">
      <div class="flex items-center gap-2 px-2">
        <span class="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/20 text-lg">🛡️</span>
        <div>
          <div class="text-sm font-semibold tracking-wide text-slate-100">Sentinel Monitor</div>
          <div class="text-[11px] uppercase tracking-widest text-slate-500">Security Ops</div>
        </div>
      </div>

      <nav class="flex gap-1 md:mt-8 md:flex-col">
        <router-link
          v-for="item in NAV"
          :key="item.name"
          :to="item.path"
          class="flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-100"
          active-class="nav-active"
        >
          <svg class="h-4 w-4 shrink-0" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" :d="item.icon" />
          </svg>
          <span class="hidden md:inline">{{ item.label }}</span>
        </router-link>
      </nav>

      <div class="flex items-center gap-3 rounded-lg bg-slate-900 px-3 py-2 md:mt-auto">
        <span class="flex h-8 w-8 items-center justify-center rounded-full bg-slate-700 text-xs font-bold text-slate-200">{{ initial }}</span>
        <div class="hidden min-w-0 md:block">
          <div class="truncate text-sm text-slate-200">{{ displayUser }}</div>
          <button class="text-xs text-cyan-400 hover:text-cyan-300" @click="signOut">Sign out</button>
        </div>
        <button class="text-xs text-cyan-400 md:hidden" @click="signOut">Sign out</button>
      </div>
    </aside>

    <main class="min-w-0 flex-1 overflow-y-auto p-4 md:p-8">
      <router-view />
    </main>
  </div>
</template>