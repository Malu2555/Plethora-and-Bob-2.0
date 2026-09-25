<script setup>
/**
 * Live audit telemetry feed (GET /api/v1/audit/ -> { items, count }).
 * Props: limit (page size), pollMs (0 disables auto-refresh).
 */
import { onMounted, onUnmounted, ref } from 'vue'

import api from '../services/api'
import logger from '../utils/logger'
import toast from '../utils/toast'

const props = defineProps({
  limit: { type: Number, default: 50 },
  pollMs: { type: Number, default: 0 },
})

const rows = ref([])
const total = ref(0)
const loading = ref(false)
const error = ref(null)

let timer = null

const SEVERITY_STYLES = {
  info: 'bg-sky-500/10 text-sky-300 border-sky-600/40',
  warning: 'bg-amber-500/10 text-amber-300 border-amber-600/40',
  critical: 'bg-red-500/10 text-red-300 border-red-600/40',
}

function formatTime(iso) {
  if (!iso) return '—'
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'medium' }).format(
    new Date(iso),
  )
}

async function refresh() {
  if (loading.value) return
  loading.value = true
  error.value = null
  try {
    const { data } = await api.get('/api/v1/audit/', { params: { limit: props.limit, offset: 0 } })
    rows.value = data.items ?? []
    total.value = data.count ?? 0
    logger.debug('audit-feed', `loaded ${rows.value.length}/${total.value}`)
  } catch (err) {
    error.value = 'Could not load the audit feed.'
    logger.error('audit-feed', err)
  } finally {
    loading.value = false
  }
}

async function loadMore() {
  if (loading.value) return
  loading.value = true
  try {
    const { data } = await api.get('/api/v1/audit/', {
      params: { limit: props.limit, offset: rows.value.length },
    })
    rows.value = [...rows.value, ...(data.items ?? [])]
    total.value = data.count ?? 0
  } catch (err) {
    toast('Could not load more events.', 'error')
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  refresh()
  if (props.pollMs > 0) timer = window.setInterval(refresh, props.pollMs)
})

onUnmounted(() => {
  if (timer) window.clearInterval(timer)
})

defineExpose({ refresh })
</script>

<template>
  <div class="card">
    <div class="flex items-center justify-between gap-2">
      <h2 class="text-xs font-semibold uppercase tracking-widest text-slate-500">
        Audit Telemetry <span class="ml-1 text-slate-600">({{ total }})</span>
      </h2>
      <button class="btn-ghost" :disabled="loading" @click="refresh">
        {{ loading ? 'Refreshing…' : 'Refresh' }}
      </button>
    </div>

    <div v-if="error" class="mt-4 rounded-lg border border-red-700 bg-red-950/60 px-4 py-3 text-sm text-red-200">
      {{ error }}
    </div>

    <ul v-else class="mt-4 divide-y divide-slate-800">
      <li v-for="row in rows" :key="row.id" class="flex items-start gap-3 py-3">
        <span
          class="mt-0.5 inline-flex items-center justify-center rounded border px-2 py-0.5 text-[11px] font-semibold uppercase"
          :class="SEVERITY_STYLES[row.severity] ?? SEVERITY_STYLES.info"
        >
          {{ row.severity }}
        </span>
        <div class="min-w-0 flex-1">
          <p class="break-words text-sm text-slate-200">{{ row.message }}</p>
          <p class="mt-0.5 text-[11px] text-slate-500">
            by {{ row.username }} · {{ formatTime(row.created_at) }}
            <span v-if="row.target_id"> · target #{{ row.target_id }}</span>
          </p>
        </div>
      </li>
      <li v-if="!loading && rows.length === 0" class="py-6 text-center text-sm text-slate-500">
        No events yet — vault activity will appear here.
      </li>
    </ul>

    <button v-if="rows.length < total" class="btn-ghost mt-2 w-full" @click="loadMore">
      Load more
    </button>
  </div>
</template>