<script setup>
/**
 * Per-user vault CRUD bound to /api/v1/vault/.
 * - list + create form on top
 * - per-row reveal / copy / inline edit / delete (204 handled silently)
 * 4xx errors are toasted by the api interceptor; 404s surface as a toast.
 */
import { onMounted, reactive, ref } from 'vue'

import api from '../services/api'
import logger from '../utils/logger'
import toast from '../utils/toast'

const records = ref([])
const loading = ref(false)

const form = reactive({ title: '', secret_data: '', revealSecret: false, busy: false })

const editingId = ref(null)
const editForm = reactive({ title: '', secret_data: '' })

const revealed = ref(new Set())

async function load() {
  loading.value = true
  try {
    const { data } = await api.get('/api/v1/vault/')
    records.value = data ?? []
    logger.debug('vault', `loaded ${records.value.length} records`)
  } catch (err) {
    logger.error('vault', 'list failed', err)
  } finally {
    loading.value = false
  }
}

async function create() {
  if (!form.title.trim() || !form.secret_data.trim()) {
    toast('Title and secret are required.', 'warning')
    return
  }
  form.busy = true
  try {
    await api.post('/api/v1/vault/', { title: form.title, secret_data: form.secret_data })
    toast(`Saved record “${form.title.trim()}”.`, 'success')
    form.title = ''
    form.secret_data = ''
    await load()
  } catch (err) {
    logger.warn('vault', 'create failed', err)
  } finally {
    form.busy = false
  }
}

async function remove(record) {
  if (!window.confirm(`Delete “${record.title}” — this cannot be undone?`)) return
  try {
    await api.delete(`/api/v1/vault/${record.id}`)
    toast(`Deleted “${record.title}”.`, 'success')
    await load()
  } catch (err) {
    toast('Delete failed (record may already be gone).', 'error')
  }
}

function startEdit(record) {
  editingId.value = record.id
  editForm.title = record.title
  editForm.secret_data = record.secret_data
}

async function saveEdit() {
  if (!editForm.title.trim() || !editForm.secret_data.trim()) {
    toast('Title and secret are required.', 'warning')
    return
  }
  try {
    const { data } = await api.patch(`/api/v1/vault/${editingId.value}`, {
      title: editForm.title,
      secret_data: editForm.secret_data,
    })
    toast(`Updated “${data.title}”.`, 'success')
    editingId.value = null
    await load()
  } catch (err) {
    toast('Update failed.', 'error')
  }
}

function toggleReveal(id) {
  if (revealed.value.has(id)) {
    revealed.value.delete(id)
  } else {
    revealed.value.add(id)
  }
}

const isRevealed = (id) => revealed.value.has(id)

async function copySecret(record) {
  try {
    await navigator.clipboard.writeText(record.secret_data)
    toast('Secret copied to clipboard.', 'info')
  } catch {
    toast('Clipboard unavailable in this browser.', 'warning')
  }
}

function formatTime(iso) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'short' }).format(
    new Date(iso),
  )
}

onMounted(load)
</script>

<template>
  <section class="space-y-4">
    <div class="card space-y-3">
      <h2 class="text-xs font-semibold uppercase tracking-widest text-slate-500">New record</h2>
      <div class="flex flex-col gap-3 lg:flex-row">
        <input
          v-model="form.title"
          class="input lg:w-64"
          placeholder="Title, e.g. prod-db"
          maxlength="200"
        />
        <div class="relative flex-1">
          <input
            v-model="form.secret_data"
            class="input w-full pr-16"
            :type="form.revealSecret ? 'text' : 'password'"
            placeholder="Secret payload…"
          />
          <button
            type="button"
            class="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-cyan-400 hover:text-cyan-300"
            @click="form.revealSecret = !form.revealSecret"
          >
            {{ form.revealSecret ? 'Hide' : 'Show' }}
          </button>
        </div>
        <button class="btn-primary" :disabled="form.busy" @click="create">
          {{ form.busy ? 'Saving…' : 'Encrypt & store' }}
        </button>
      </div>
    </div>

    <div class="card">
      <div class="flex items-center justify-between">
        <h2 class="text-xs font-semibold uppercase tracking-widest text-slate-500">
          My records ({{ records.length }})
        </h2>
        <button class="btn-ghost" :disabled="loading" @click="load">{{ loading ? 'Loading…' : 'Refresh' }}</button>
      </div>

      <ul class="mt-4 divide-y divide-slate-800">
        <li v-for="record in records" :key="record.id" class="py-3">
          <div v-if="editingId === record.id" class="space-y-2">
            <input v-model="editForm.title" class="input w-full sm:w-72" placeholder="Title" maxlength="200" />
            <textarea v-model="editForm.secret_data" rows="2" class="input w-full" placeholder="Secret payload…"></textarea>
            <div class="flex gap-2">
              <button class="btn-primary" @click="saveEdit">Save</button>
              <button class="btn-ghost" @click="editingId = null">Cancel</button>
            </div>
          </div>

          <div v-else class="flex flex-wrap items-center gap-3">
            <div class="min-w-0 flex-1">
              <p class="text-sm font-medium text-slate-100">{{ record.title }}</p>
              <p class="text-xs text-slate-500">
                #{{ record.id }} · {{ formatTime(record.created_at) }} · secret:
                <span v-if="isRevealed(record.id)" class="break-all font-mono text-cyan-300">{{ record.secret_data }}</span>
                <span v-else>••••••••</span>
              </p>
            </div>
            <div class="flex items-center gap-1">
              <button class="btn-ghost" @click="toggleReveal(record.id)">
                {{ isRevealed(record.id) ? 'Mask' : 'Reveal' }}
              </button>
              <button class="btn-ghost" @click="copySecret(record)">Copy</button>
              <button class="btn-ghost" @click="startEdit(record)">Edit</button>
              <button class="btn-danger" @click="remove(record)">Delete</button>
            </div>
          </div>
        </li>
        <li v-if="!loading && records.length === 0" class="py-6 text-center text-sm text-slate-500">
          Your vault is empty — store your first secret above.
        </li>
      </ul>
    </div>
  </section>
</template>