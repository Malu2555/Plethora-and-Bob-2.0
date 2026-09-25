/**
 * Routes: /login and /register are public; everything else sits behind the
 * JWT guard inside AppShell and requires a stored access token. Expiry while
 * navigating is handled in-place by the axios interceptor (silent refresh ->
 * retry).
 */
import { createRouter, createWebHistory } from 'vue-router'

import AppShell from '../components/AppShell.vue'
import { getAccessToken } from '../utils/session'

import AuditPage from '../views/AuditPage.vue'
import DashboardPage from '../views/DashboardPage.vue'
import LoginPage from '../views/LoginPage.vue'
import RegisterPage from '../views/RegisterPage.vue'
import SecurityPage from '../views/SecurityPage.vue'
import VaultPage from '../views/VaultPage.vue'

const routes = [
  { path: '/login', name: 'login', component: LoginPage, meta: { public: true } },
  { path: '/register', name: 'register', component: RegisterPage, meta: { public: true } },
  {
    path: '/',
    component: AppShell,
    children: [
      { path: '', name: 'dashboard', component: DashboardPage },
      { path: 'vault', name: 'vault', component: VaultPage },
      { path: 'security', name: 'security', component: SecurityPage },
      { path: 'audit', name: 'audit', component: AuditPage },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to) => {
  const authed = Boolean(getAccessToken())

  // Protected route without a token? -> login, remembering the destination.
  if (!to.meta.public && !authed) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }

  // Already signed in and visiting a public auth page? -> dashboard.
  if ((to.name === 'login' || to.name === 'register') && authed) {
    return { name: 'dashboard' }
  }

  return true
})

export default router
