<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Check, KeyRound, LogOut, ShieldAlert } from '@lucide/vue'
import { APIError } from '../api/client'
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()
const router = useRouter()
const oldPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const error = ref('')
const saving = ref(false)
const rules = computed(() => ({
  length: newPassword.value.length >= 12,
  mixed: /[A-Za-z]/.test(newPassword.value) && /\d|[^A-Za-z0-9]/.test(newPassword.value),
  same: newPassword.value.length > 0 && newPassword.value === confirmPassword.value,
}))

async function submit() {
  error.value = ''
  if (!rules.value.length || !rules.value.mixed || !rules.value.same) {
    error.value = '请满足全部密码要求'
    return
  }
  saving.value = true
  try {
    await auth.changePassword(oldPassword.value, newPassword.value)
    await router.replace({ name: 'login', query: { changed: '1' } })
  } catch (reason) {
    error.value = reason instanceof APIError ? reason.message : '密码修改失败'
  } finally {
    saving.value = false
  }
}

async function logout() {
  await auth.logout()
  await router.replace({ name: 'login' })
}
</script>

<template>
  <main class="password-page">
    <section class="password-card">
      <div class="password-icon"><ShieldAlert :size="30" /></div>
      <p class="eyebrow">FIRST SIGN-IN</p>
      <h1>先更新初始密码</h1>
      <p class="muted">为了完成管理员身份初始化，请设置仅你知晓的新密码。更新后需要重新登录。</p>
      <form @submit.prevent="submit">
        <label class="field-label" for="old-password">初始密码</label>
        <div class="input-shell"><KeyRound :size="18" /><input id="old-password" v-model="oldPassword" type="password" autocomplete="current-password" required /></div>
        <label class="field-label" for="new-password">新密码</label>
        <div class="input-shell"><KeyRound :size="18" /><input id="new-password" v-model="newPassword" type="password" autocomplete="new-password" required /></div>
        <label class="field-label" for="confirm-password">确认新密码</label>
        <div class="input-shell"><KeyRound :size="18" /><input id="confirm-password" v-model="confirmPassword" type="password" autocomplete="new-password" required /></div>
        <ul class="password-rules">
          <li :class="{ passed: rules.length }"><Check :size="15" /> 至少 12 个字符</li>
          <li :class="{ passed: rules.mixed }"><Check :size="15" /> 同时包含字母与数字或符号</li>
          <li :class="{ passed: rules.same }"><Check :size="15" /> 两次输入保持一致</li>
        </ul>
        <p v-if="error" class="form-error" role="alert">{{ error }}</p>
        <button class="primary-button full-button" type="submit" :disabled="saving">{{ saving ? '正在更新…' : '更新密码并重新登录' }}</button>
      </form>
      <button class="text-button" type="button" @click="logout"><LogOut :size="16" /> 退出当前会话</button>
    </section>
  </main>
</template>
