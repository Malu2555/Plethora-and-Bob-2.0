/**
 * Application bootstrap: Pinia (state) + Vue Router + global styles.
 */
import { createApp } from 'vue'
import { createPinia } from 'pinia'

import App from './App.vue'
import router from './router'
import logger from './utils/logger'

import './style.css'

const app = createApp(App)

app.use(createPinia())
app.use(router)
app.mount('#app')

logger.info('app', 'Sentinel Monitor frontend mounted')
