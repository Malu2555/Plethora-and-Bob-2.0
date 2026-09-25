<script setup>
/**
 * Audit page: the full append-only telemetry feed with 15s auto-refresh.
 */
import AuditLogFeed from '../components/AuditLogFeed.vue'
</script>

<template>
  <section class="space-y-4">
    <header>
      <h1 class="text-lg font-semibold text-slate-100">Audit Log</h1>
      <p class="text-xs text-slate-500">
        Append-only telemetry written by the backend — read-only through the API.
      </p>
    </header>
    <AuditLogFeed :limit="50" :poll-ms="15000" />
  </section>
</template>