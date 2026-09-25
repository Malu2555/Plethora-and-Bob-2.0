<script setup>
/**
 * Dashboard: posture gauge + audit telemetry tiles + metric tiles + live
 * (polling) audit feed — rendered from GET /api/v1/security/posture and
 * GET /api/v1/audit/. The scanner stream (static findings) previews in a
 * summary strip and lives in full on /security.
 */
import { onMounted, ref } from 'vue'

import api from '../services/api'
import logger from '../utils/logger'

import AuditLogFeed from '../components/AuditLogFeed.vue'
import AuditTelemetryTiles from '../components/AuditTelemetryTiles.vue'
import MetricsTiles from '../components/MetricsTiles.vue'
import PostureScoreGauge from '../components/PostureScoreGauge.vue'

const posture = ref(null)
const loading = ref(true)
const error = ref(null)

async function refresh() {
  loading.value = true
  error.value = null
  try {
    const { data } = await api.get('/api/v1/security/posture')
    posture.value = data
  } catch (err) {
    error.value = 'Could not load the posture snapshot.'
    logger.error('dashboard', err)
  } finally {
    loading.value = false
  }
}

onMounted(refresh)
</script>

<template>
  <section class="space-y-4">
    <header class="flex items-center justify-between gap-2">
      <div>
        <h1 class="text-lg font-semibold text-slate-100">Security Posture</h1>
        <p class="text-xs text-slate-500">24-hour snapshot aggregated by the backend</p>
      </div>
      <button class="btn-ghost" :disabled="loading" @click="refresh">{{ loading ? 'Loading…' : 'Refresh' }}</button>
    </header>

    <div v-if="error" class="rounded-lg border border-red-700 bg-red-950/60 px-4 py-3 text-sm text-red-200">
      {{ error }}
    </div>

    <template v-if="posture">
      <div class="grid gap-4 lg:grid-cols-3">
        <PostureScoreGauge
          :score="posture.posture_score"
          :findings-deduction="posture.findings_deduction"
          :audit-deduction="posture.audit_deduction"
        />
        <AuditTelemetryTiles
          :critical="posture.critical"
          :high="posture.high"
          :medium="posture.medium"
          :low="posture.low"
          :info="posture.info"
        />
      </div>
      <MetricsTiles
        :vault-count="posture.vault_count"
        :audit-events-24h="posture.audit_events_24h"
        :last-event-at="posture.last_event_at"
      />
      <router-link
        :to="{ name: 'security' }"
        class="card flex items-center justify-between gap-4 border-cyan-800/50 transition-colors hover:bg-slate-900"
      >
        <div>
          <div class="text-xs font-semibold uppercase tracking-widest text-slate-500">Code Findings</div>
          <div class="mt-1 text-sm text-slate-300">
            <span v-if="posture.findings_total > 0" class="font-semibold text-red-300">{{ posture.findings_total }}</span>
            <span v-else class="font-semibold text-emerald-300">0</span>
            open finding{{ posture.findings_total === 1 ? '' : 's' }} ·
            {{ posture.last_scan_finished_at ? `last scan ${new Date(posture.last_scan_finished_at).toLocaleString()}` : 'tree never scanned' }}
          </div>
        </div>
        <span class="text-cyan-400">View scanner →</span>
      </router-link>
      <AuditLogFeed :limit="8" :poll-ms="20000" />
    </template>

    <div v-else-if="loading" class="card py-10 text-center text-sm text-slate-500">Loading snapshot…</div>
  </section>
</template>