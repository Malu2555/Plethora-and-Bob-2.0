/**
 * Zero-dependency structured logger for the Sentinel frontend.
 *
 * Behaviour:
 *   * level filtering: debug < info < warn < error < silent
 *   * silent by default in production builds (import.meta.env.PROD) unless
 *     VITE_LOG_LEVEL overrides it
 *   * every line is prefixed `[sentinel:LEVEL] (scope)` for grep-ability
 *
 * Usage:
 *   import logger from '@/utils/logger'
 *   logger.info('vault', 'records loaded', count)
 */
const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 }

const CONSOLE = {
  debug: console.debug.bind(console),
  info: console.info.bind(console),
  warn: console.warn.bind(console),
  error: console.error.bind(console),
}

const PRODUCTION = import.meta.env.PROD
const configured = import.meta.env.VITE_LOG_LEVEL ?? (PRODUCTION ? 'silent' : 'debug')

let current = configured in LEVELS ? configured : 'debug'

function emit(level, scope, args) {
  if (LEVELS[level] < LEVELS[current]) return
  const fn = CONSOLE[level] ?? console.log
  fn(`[sentinel:${level.toUpperCase()}] (${scope})`, ...args)
}

const logger = {
  get level() {
    return current
  },

  setLevel(name) {
    if (name in LEVELS) {
      current = name
    }
  },

  debug: (scope, ...args) => emit('debug', scope, args),
  info: (scope, ...args) => emit('info', scope, args),
  warn: (scope, ...args) => emit('warn', scope, args),
  error: (scope, ...args) => emit('error', scope, args),
}

export default logger
