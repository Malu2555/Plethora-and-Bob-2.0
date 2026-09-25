/**
 * Zero-dependency toast notifications (bottom-right stack).
 *
 * Usage:
 *   import toast from '@/utils/toast'
 *   toast('Saved', 'success')
 *   toast('Something failed', 'error')
 */
import logger from './logger'

const STYLES = {
  info: 'border-slate-600 bg-slate-800 text-slate-100',
  success: 'border-emerald-600 bg-emerald-900/90 text-emerald-100',
  warning: 'border-amber-600 bg-amber-900/90 text-amber-100',
  error: 'border-red-600 bg-red-900/90 text-red-100',
}

let container = null

function ensureContainer() {
  if (container) return container
  container = document.createElement('div')
  container.className = 'fixed bottom-4 right-4 z-[100] flex w-80 flex-col gap-2'
  document.body.appendChild(container)
  return container
}

export function toast(message, kind = 'info', ttl = 4500) {
  const host = ensureContainer()
  const node = document.createElement('div')
  node.className = `rounded-lg border px-4 py-3 text-sm shadow-xl transition-opacity ${
    STYLES[kind] ?? STYLES.info
  }`
  node.textContent = message
  host.appendChild(node)

  logger.info('toast', `${kind}: ${message}`)

  window.setTimeout(() => {
    node.style.opacity = '0'
    window.setTimeout(() => node.remove(), 300)
  }, ttl)
}

export default toast
