<script setup>

/**
 * Seven rule tiles for the security scanner (GET /security/findings).
 * Purely observational: click opens a drill-down panel with evidence and
 * prose guidance -- no fixes are offered and nothing touches the codebase.
 */
import { computed, ref } from 'vue'

const props = defineProps({
  byRule: { type: Array, default: () => [] },
  items: { type: Array, default: () => [] },
  total: { type: Number, default: 0 },
})

const SEVERITY_LABELS = {
  critical: 'Critical',
  high: 'High',
  warning: 'Warning',
  info: 'Info',
}

const SEVERITY_TEXT = {
  critical: 'text-red-300',
  high: 'text-orange-300',
  warning: 'text-amber-300',
  info: 'text-sky-300',
}

const SEVERITY_BORDER = {
  critical: 'border-red-600/60 bg-red-500/10',
  high: 'border-orange-600/60 bg-orange-500/10',
  warning: 'border-amber-600/60 bg-amber-500/10',
  info: 'border-sky-600/60 bg-sky-500/10',
}

const selected = ref(null)

const selectedRule = computed(() =>
  props.byRule.find((rule) => rule.rule_id === selected.value) ?? null,
)

const selectedItems = computed(() => {
  if (!selectedRule.value) return []
  return props.items.filter((item) => item.rule_id === selectedRule.value.rule_id)
})

function select(rule) {
  selected.value = selected.value === rule.rule_id ? null : rule.rule_id
}

const locationLabel = (item) =>
  item.file_path ? `${item.file_path}${item.line_no ? `:${item.line_no}` : ''}` : 'runtime probe'
</script>

<template>
  <section class="space-y-4">
    <div class="rounded-lg border border-slate-700 bg-slate-900/60 px-4 py-3 text-xs text-slate-400">
      🛡️ Observational only — this dashboard reads scan snapshots from the backend and never
      modifies your code. Fixes are your move; the panel below explains why each finding matters.
    </div>

    <div v-if="total === 0" class="card flex items-center gap-4 py-8">
      <span class="text-4xl">🎉</span>
      <div>
        <div class="text-lg font-semibold text-emerald-300">Clean tree — nothing to report</div>
        <div class="mt-1 text-xs text-slate-500">
          All 7 scanner rules passed on the latest snapshot. Run a fresh scan anytime.
        </div>
      </div>
    </div>

    <template v-else>
      <div class="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
        <button
          v-for="rule in byRule"
          :key="rule.rule_id"
          type="button"
          class="flex flex-col items-center gap-1 rounded-lg border px-2 py-4 text-center transition-colors"
          :class="[
            rule.count > 0
              ? SEVERITY_BORDER[rule.severity] ?? SEVERITY_BORDER.info
              : 'border-slate-700/70 bg-slate-900/40 hover:bg-slate-800/60',
            selected === rule.rule_id ? 'ring-2 ring-cyan-400/70' : '',
          ]"
          :title="`${rule.label} — ${SEVERITY_LABELS[rule.severity] ?? rule.severity} · weight ${rule.weight}`"
          @click="select(rule)"
        >
          <span
            class="text-2xl font-bold tabular-nums"
            :class="rule.count > 0 ? SEVERITY_TEXT[rule.severity] ?? 'text-slate-200' : 'text-slate-600'"
          >{{ rule.count }}</span>
          <span class="text-[11px] font-medium leading-tight text-slate-300">{{ rule.label }}</span>
          <span class="text-[10px] uppercase tracking-wide text-slate-500">-{{ rule.weight }} pts each</span>
        </button>
      </div>

      <div v-if="selectedRule" class="card">
        <div class="flex items-center justify-between gap-2">
          <h3 class="text-sm font-semibold text-slate-100">
            {{ selectedRule.label }}
            <span class="ml-2 rounded-full bg-slate-800 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
              {{ selectedItems.length }} finding{{ selectedItems.length === 1 ? '' : 's' }}
            </span>
          </h3>
          <button class="btn-ghost text-xs" @click="selected = null">Close</button>
        </div>

        <p v-if="selectedItems.length === 0" class="mt-3 text-xs text-emerald-300">
          No open findings for this rule on the latest scan.
        </p>

        <ul v-else class="mt-4 space-y-3">
          <li
            v-for="item in selectedItems"
            :key="item.id"
            class="rounded-lg border border-slate-800 bg-slate-950/60 p-3"
          >
            <div class="flex flex-wrap items-center gap-2">
              <code class="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-cyan-300">{{ locationLabel(item) }}</code>
              <span class="text-[11px] uppercase tracking-wide" :class="SEVERITY_TEXT[item.severity] ?? 'text-slate-400'">
                {{ SEVERITY_LABELS[item.severity] ?? item.severity }}
              </span>
            </div>
            <p class="mt-2 text-sm text-slate-300">{{ item.message }}</p>
            <div class="mt-3 space-y-2 border-t border-slate-800 pt-3">
              <p class="text-xs text-slate-400">
                <span class="font-semibold text-slate-200">Why this matters:</span> {{ item.why }}
              </p>
              <p class="text-xs text-slate-400">
                <span class="font-semibold text-slate-200">Recommended direction:</span> {{ item.recommended }}
              </p>
            </div>
          </li>
        </ul>
      </div>

      <p v-else class="text-xs text-slate-500">Select a rule tile to inspect its findings and guidance.</p>
    </template>
  </section>
</template>
