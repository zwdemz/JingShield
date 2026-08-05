import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from './stores/auth'
import { pinia } from './stores'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    { path: '/login', name: 'login', component: () => import('./views/LoginView.vue'), meta: { public: true } },
    { path: '/change-password', name: 'change-password', component: () => import('./views/ChangePasswordView.vue') },
    {
      path: '/',
      component: () => import('./layouts/AdminLayout.vue'),
      children: [
        { path: '', name: 'dashboard', component: () => import('./views/DashboardView.vue') },
        { path: 'attacks', name: 'attacks', component: () => import('./views/AttackLogsView.vue') },
        { path: 'access', name: 'access', component: () => import('./views/AccessLogsView.vue') },
        { path: 'sites', name: 'sites', component: () => import('./views/SitesView.vue') },
        { path: 'ip-list', name: 'ip-list', component: () => import('./views/IPListView.vue') },
        { path: 'policies', name: 'policies', component: () => import('./views/PolicyView.vue') },
        { path: 'settings', name: 'settings', component: () => import('./views/SettingsView.vue') },
		{ path: 'users', name: 'users', component: () => import('./views/UsersView.vue') },
		{ path: 'integration', name: 'integration', component: () => import('./views/IntegrationView.vue') },
      ],
    },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach(async (to) => {
  const auth = useAuthStore(pinia)
  await auth.restore()
  if (to.meta.public) {
    if (auth.authenticated) return auth.mustChangePassword ? { name: 'change-password' } : { name: 'dashboard' }
    return true
  }
  if (!auth.authenticated) return { name: 'login', query: { redirect: to.fullPath } }
  if (auth.mustChangePassword && to.name !== 'change-password') return { name: 'change-password' }
  return true
})

export default router
