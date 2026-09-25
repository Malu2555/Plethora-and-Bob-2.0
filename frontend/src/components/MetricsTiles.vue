<script setup>
/**
 * Compact metric tiles: vault size, 24h audit volume, last event timestamp.
 */
import { computed } from 'vue'

const props = defineProps({
  vaultCount: { type: Number, default: 0 },
  auditEvents24h: { type: Number, default: 0 },
  lastEventAt: { type: String, default: null },
})

const lastEventLabel = computed(() => {
  if (!props.lastEventAt) return '—'
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    new Date(props.lastEventAt),
  )
})

const TILES = [
  { key: 'vault', label: 'Vault records', value: () => props.vaultCount, icon: 'M12 3l8 4v5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V7l8-4z' },
  { key: 'audit', label: 'Audit events / 24h', value: () => props.auditEvents24h, icon: 'M4 6h16M4 12h10M4 18h7' },
  { key: 'last', label: 'Last event', value: () => lastEventLabel.value, icon: 'M12 8v4l2 2M21 12a9 9 0 11-18 0 9 9 0 0118 0z' },
]
</script>

<template>
  <div class="grid gap-4 sm:grid-cols-3">
    <div v-for="tile in TILES" :key="tile.key" class="card flex items-center gap-4">
      <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-300">
        <svg class="h-5 w-5" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" :d="tile.icon" />
        </svg>
      </span>
      <div class="min-w-0">
        <div class="truncate text-xl font-bold tabular-nums text-slate-100">{{ tile.value() }}</div>
        <div class="text-xs text-slate-500">{{ tile.label }}</div>
      </div>
    </div>
  </div>
</template>