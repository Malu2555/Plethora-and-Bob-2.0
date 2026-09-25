<script setup>
/**
 * Circular SVG gauge for the 0-100 security posture score.
 * Colour bands: >=80 emerald, >=50 amber, below red.
 * The score formula (100 - 25*critical - 15*high, floored at 0) lives in the
 * backend and is reprinted here for the operator's convenience.
 */
import { computed } from 'vue'

const props = defineProps({
  score: { type: Number, required: true },
  findingsDeduction: { type: Number, default: 0 },
  auditDeduction: { type: Number, default: 0 },
})

const CIRCUMFERENCE = 2 * Math.PI * 54 // r = 54 viewBox units

const clamped = computed(() => Math.max(0, Math.min(100, props.score)))
const dashOffset = computed(() => CIRCUMFERENCE * (1 - clamped.value / 100))

const attribution = computed(() => {
  const parts = [
    props.findingsDeduction > 0 ? `−${props.findingsDeduction} findings` : null,
    props.auditDeduction > 0 ? `−${props.auditDeduction} audit events` : null,
  ].filter(Boolean)
  return parts.length ? parts.join(' · ') : 'no deductions — clean'
})

const band = computed(() => {
  if (clamped.value >= 80) return { stroke: '#34d399', text: 'text-emerald-300', label: 'Good' }
  if (clamped.value >= 50) return { stroke: '#fbbf24', text: 'text-amber-300', label: 'Caution' }
  return { stroke: '#f87171', text: 'text-red-300', label: 'Critical' }
})
</script>

<template>
  <div class="card flex flex-col items-center gap-2">
    <h2 class="self-start text-xs font-semibold uppercase tracking-widest text-slate-500">Posture Score</h2>

    <div class="relative">
      <svg width="160" height="160" viewBox="0 0 128 128" role="img" aria-label="Posture score gauge">
        <circle cx="64" cy="64" r="54" fill="none" stroke="#1e293b" stroke-width="10" />
        <circle
          cx="64"
          cy="64"
          r="54"
          fill="none"
          :stroke="band.stroke"
          stroke-width="10"
          stroke-linecap="round"
          :stroke-dasharray="CIRCUMFERENCE"
          :stroke-dashoffset="dashOffset"
          transform="rotate(-90 64 64)"
        />
      </svg>
      <div class="absolute inset-0 flex flex-col items-center justify-center">
        <span class="text-4xl font-bold tabular-nums text-slate-100">{{ clamped }}</span>
        <span :class="band.text" class="text-xs font-medium">{{ band.label }}</span>
      </div>
    </div>

    <p
      class="text-center text-xs text-slate-500"
      :title="`posture = max(0, 100 − findings (capped 80) − 25·critical − 15·high); ${attribution}`"
    >
      {{ attribution }}
    </p>
  </div>
</template>