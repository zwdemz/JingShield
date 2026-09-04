import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { APIError, apiRequest, jsonBody, setCSRFToken } from '../api/client'
import type { SessionUser } from '../types/api'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<SessionUser | null>(null)
  const initialized = ref(false)
  const loading = ref(false)

  const authenticated = computed(() => user.value !== null)
  const mustChangePassword = computed(() => user.value?.must_change_password === true)

  function applySession(session: SessionUser) {
    user.value = session
    setCSRFToken(session.csrf_token)
  }

  async function restore() {
    if (initialized.value) return
    try {
      applySession(await apiRequest<SessionUser>('/auth/me'))
    } catch (error) {
      if (!(error instanceof APIError) || error.status !== 401) console.warn(error)
      clear()
    } finally {
      initialized.value = true
    }
  }

  async function login(username: string, password: string) {
    loading.value = true
    try {
      const session = await apiRequest<SessionUser>('/auth/login', {
        method: 'POST',
        ...jsonBody({ username, password }),
      })
      applySession(session)
      initialized.value = true
      return session
    } finally {
      loading.value = false
    }
  }

  async function logout() {
    try {
      if (user.value) await apiRequest<null>('/auth/logout', { method: 'POST' })
    } finally {
      clear()
    }
  }

  async function changePassword(oldPassword: string, newPassword: string) {
    await apiRequest<null>('/users/password', {
      method: 'PUT',
      ...jsonBody({ old_password: oldPassword, new_password: newPassword }),
    })
    clear()
  }

  function clear() {
    user.value = null
    setCSRFToken('')
  }

  return { user, loading, initialized, authenticated, mustChangePassword, restore, login, logout, changePassword, clear }
})
