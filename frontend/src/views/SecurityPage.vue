<script setup>
/**
 * Security findings page: per-rule scanner tiles, drill-down guidance and the
 * scan history. POST /security/scan queues a background job; the page polls
 * the run history until the placeholder run completes.
 */
import { onMounted, onUnmounted, ref } from 'vue'

import api from '../services/api'
import logger from '../utils/logger'
import toast from '../utils/toast'

import SecurityFindingsTiles from '../components/SecurityFindingsTiles.vue'

const snapshot = ref(null)
const runs = ref([])
const loading = ref(true)
const error = ref(null)
const scanning = ref(false)

let pollTimer = null

async function refresh() {
  try {
    const [{ data: findings }, { data: history }] = await Promise.all([
      api.get('/api/v1/security/findings'),
      api.get('/api/v1/security/scan/runs'),
    ])
    snapshot.value = findings
    runs.value = history.items
    error.value = null
  } catch (err) {
    error.value = 'Could not load the security scan data.'
    logger.error('security', err)
  } finally {
    loading.value = false
  }
}

function formatWhen(iso) {
  if (!iso) return 'â€”'
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    new Date(iso),
  )
}

function exitBadge(run) {
  if (run.finished_at === null) {
    return { label: 'running', classes: 'border-amber-500/40 bg-amber-500/10 text-amber-300' }
  }
  if (run.exit_code === 0) {
    return { label: 'clean', classes: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300' }
  }
  return { label: 'findings', classes: 'border-red-500/40 bg-red-500/10 text-red-300' }
}

async function runScan() {
  if (scanning.value) return
  scanning.value = true
  error.value = null
  try {
    const { data } = await api.post('/api/v1/security/scan', {
      trigger: 'dashboard',
      runtime_probe: true,
      collect_tests: false,
    })
    toast(`Scan queued (run #${data.scan_run_id}) â€” dashboard will update when it finishes.`, 'info')
    pollUntilDone(data.scan_run_id)
  } catch (err) {
    error.value = 'Could not start the scan.'
    logger.error('security', err)
    scanning.value = false
  }
}

async function pollUntilDone(runId) {
  try {
    const { data } = await api.get('/api/v1/security/scan/runs')
    const run = data.items.find((item) => item.id === runId)
    if (run && run.finished_at !== null) {
      scanning.value = false
      await refresh()
      toast(
        run.exit_code === 0
          ? 'Scan complete â€” clean tree, exit code 0.'
          : `Scan complete â€” ${run.findings_total} finding(s), exit code ${run.exit_code}.`,
        run.exit_code === 0 ? 'success' : 'warning',
      )
      return
    }
    pollTimer = setTimeout(() => pollUntilDone(runId), 2000)
  } catch (err) {
    logger.error('security', err)
    scanning.value = false
  }
}

function ensurePolling() {
  // A run started elsewhere (CLI/another tab) also deserves live polling.
  const current = snapshot.value?.scan
  if (current && current.finished_at === null && !scanning.value) {
    scanning.value = true
    pollUntilDone(current.id)
  }
}

onMounted(async () => {
  await refresh()
  ensurePolling()
})

onUnmounted(() => {
  if (pollTimer) clearTimeout(pollTimer)
})
</script>

<template>
  <section class="space-y-4">
    <header class="flex items-center justify-between gap-2">
      <div>
        <h1 class="text-lg font-semibold text-slate-100">Security Findings</h1>
        <p class="text-xs text-slate-500">
          Static scanner snapshots — seven vulnerability classes, scored per rule, prose-only guidance.
        </p>
      </div>
      <button class="btn-primary" :disabled="scanning || loading" @click="runScan">
        {{ scanning ? 'Scanning…' : 'Run scan' }}
      </button>
    </header>

    <div v-if="error" class="rounded-lg border border-red-700 bg-red-950/60 px-4 py-3 text-sm text-red-200">
      {{ error }}
    </div>

    <div v-if="loading" class="card py-10 text-center text-sm text-slate-500">Loading security data…</div>

    <template v-else-if="snapshot">
      <SecurityFindingsTiles
        :by-rule="snapshot.by_rule"
        :items="snapshot.items"
        :total="snapshot.total"
      />

      <div class="card">
        <div class="flex items-center justify-between">
          <h2 class="text-xs font-semibold uppercase tracking-widest text-slate-500">Scan History</h2>
          <span v-if="snapshot.findings_deduction" class="text-xs text-slate-400">
            latest snapshot deducts
            <span class="font-semibold text-red-300">{{ snapshot.findings_deduction }} pts</span>
            from the posture score
          </span>
        </div>

        <p v-if="runs.length === 0" class="mt-3 text-xs text-slate-500">
          No scans recorded — press "Run scan" for the first snapshot.
        </p>

        <ul v-else class="mt-4 space-y-2">
          <li
            v-for="run in runs"
            :key="run.id"
            class="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs"
          >
            <div class="flex flex-wrap items-center gap-2">
              <span
                class="rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
                :class="exitBadge(run).classes"
              >{{ exitBadge(run).label }}</span>
              <span class="text-slate-300">run #{{ run.id }}</span>
              <span class="text-slate-500">branch <code class="font-mono">{{ run.branch }}</code></span>
              <span class="text-slate-500">via {{ run.trigger }}</span>
            </div>
            <div class="text-slate-500">
              <span v-if="run.finished_at === null">started {{ formatWhen(run.started_at) }}</span>
              <span v-else>{{ formatWhen(run.started_at) }} → {{ formatWhen(run.finished_at) }}</span>
              <span class="ml-2">· {{ run.findings_total }} finding(s)</span>
              <span v-if="run.exit_code !== null" class="ml-2">· exit {{ run.exit_code }}</span>
            </div>
          </li>
        </ul>
      </div>
    </template>
  </section>
</template>


