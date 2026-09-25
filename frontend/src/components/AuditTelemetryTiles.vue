<script setup>
/**
 * Five severity counters fed by the posture snapshot (GET /security/posture).
 * Renamed from VulnerabilityCounters to make the two data streams explicit:
 * these tiles show RUNTIME telemetry (audit events, 24h window) while the
 * scanner's static findings render on SecurityFindingsTiles.vue.
 * medium/low are reserved for future integrations and stay 0 today.
 */
defineProps({
  critical: { type: Number, default: 0 },
  high: { type: Number, default: 0 },
  medium: { type: Number, default: 0 },
  low: { type: Number, default: 0 },
  info: { type: Number, default: 0 },
})

const BADGES = [
  { key: 'critical', label: 'Critical', classes: 'border-red-600/60 bg-red-500/10 text-red-300' },
  { key: 'high', label: 'High', classes: 'border-orange-600/60 bg-orange-500/10 text-orange-300' },
  { key: 'medium', label: 'Medium', classes: 'border-amber-600/60 bg-amber-500/10 text-amber-300' },
  { key: 'low', label: 'Low', classes: 'border-yellow-600/60 bg-yellow-500/10 text-yellow-300' },
  { key: 'info', label: 'Info', classes: 'border-sky-600/60 bg-sky-500/10 text-sky-300' },
]
</script>

<template>
  <div class="card">
    <h2 class="text-xs font-semibold uppercase tracking-widest text-slate-500">Audit Telemetry (24h)</h2>
    <div class="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-5">
      <div
        v-for="badge in BADGES"
        :key="badge.key"
        class="flex flex-col items-center gap-1 rounded-lg border px-3 py-4"
        :class="badge.classes"
      >
        <span class="text-3xl font-bold tabular-nums">{{ $props[badge.key] }}</span>
        <span class="text-[11px] font-medium uppercase tracking-wide">{{ badge.label }}</span>
      </div>
    </div>
  </div>
</template>
