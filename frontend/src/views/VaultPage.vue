<script setup>
/**
 * Vault page: per-user secret CRUD (VaultList handles all interactions).
 */
import VaultList from '../components/VaultList.vue'
</script>

<template>
  <section class="space-y-4">
    <header>
      <h1 class="text-lg font-semibold text-slate-100">Vault</h1>
      <p class="text-xs text-slate-500">
        Secrets scoped to your account — every mutation lands in the audit trail.
      </p>
    </header>
    <VaultList />
  </section>
</template>