<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { KeyRound, Plus, RefreshCw, ShieldCheck, UserRoundCog, X } from '@lucide/vue'
import { apiRequest, jsonBody } from '../api/client'
import { useAuthStore } from '../stores/auth'
import type { UserItem } from '../types/api'

const auth = useAuthStore()
const users = ref<UserItem[]>([])
const loading = ref(false)
const saving = ref(false)
const error = ref('')
const notice = ref('')
const dialog = ref<'create' | 'password' | null>(null)
const target = ref<UserItem | null>(null)
const form = reactive({ username: '', email: '', password: '' })

async function load() {
  loading.value = true
  try { users.value = await apiRequest<UserItem[]>('/users'); error.value = '' }
  catch (reason) { error.value = reason instanceof Error ? reason.message : '用户列表加载失败' }
  finally { loading.value = false }
}

function randomPassword() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%_-'
  const bytes = crypto.getRandomValues(new Uint8Array(20))
  form.password = Array.from(bytes, (byte) => chars[byte % chars.length]).join('')
}

function openCreate() {
  target.value = null
  Object.assign(form, { username: '', email: '', password: '' })
  randomPassword()
  dialog.value = 'create'
}

function openReset(user: UserItem) {
  target.value = user
  form.password = ''
  randomPassword()
  dialog.value = 'password'
}

async function save() {
  saving.value = true
  error.value = ''
  try {
    if (dialog.value === 'create') {
      await apiRequest<UserItem>('/users', { method: 'POST', ...jsonBody(form) })
      notice.value = `管理员 ${form.username} 已创建，请安全传递临时密码`
    } else if (target.value) {
      await apiRequest<null>(`/users/${target.value.id}/password`, { method: 'PUT', ...jsonBody({ new_password: form.password }) })
      notice.value = `${target.value.username} 的会话已失效，下次登录必须修改密码`
    }
    dialog.value = null
    await load()
  } catch (reason) { error.value = reason instanceof Error ? reason.message : '保存失败' }
  finally { saving.value = false }
}

async function toggle(user: UserItem) {
  const enabled = user.status !== 1
  if (!window.confirm(`确认${enabled ? '启用' : '停用'}管理员“${user.username}”？`)) return
  try {
    await apiRequest<null>(`/users/${user.id}/status`, { method: 'PUT', ...jsonBody({ enabled }) })
    user.status = enabled ? 1 : 0
    notice.value = `${user.username} 已${enabled ? '启用' : '停用'}`
  } catch (reason) { error.value = reason instanceof Error ? reason.message : '状态更新失败' }
}

function formatTime(value: string | null) { return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '从未登录' }
onMounted(load)
</script>

<template>
  <section class="page-content">
    <header class="page-header"><div><p class="eyebrow">ADMIN ACCOUNTS</p><h1>用户管理</h1><p>维护控制台管理员、登录状态与首次改密要求。</p></div><div class="header-actions"><button class="secondary-button" :disabled="loading" @click="load"><RefreshCw :size="17" :class="{ spinning: loading }" /> 刷新</button><button class="primary-button" @click="openCreate"><Plus :size="17" /> 添加管理员</button></div></header>
    <p v-if="error" class="inline-alert">{{ error }}</p><p v-if="notice" class="inline-success">{{ notice }}</p>
    <article class="panel table-panel"><div class="table-meta"><span>管理员账号</span><strong>{{ users.length }} 个账号</strong></div><div class="table-scroll"><table><thead><tr><th>用户</th><th>状态</th><th>密码策略</th><th>最近登录</th><th>创建时间</th><th>操作</th></tr></thead><tbody><tr v-for="user in users" :key="user.id"><td><strong>{{ user.username }}</strong><small>{{ user.email || '未设置邮箱' }}</small></td><td><span class="account-state" :class="{ active: user.status === 1 }"><i></i>{{ user.status === 1 ? '已启用' : '已停用' }}</span></td><td>{{ user.must_change_password ? '登录后强制修改' : '已设置' }}</td><td>{{ formatTime(user.last_login_at) }}</td><td>{{ formatTime(user.created_at) }}</td><td><div class="row-actions"><button class="secondary-button compact-button" :disabled="user.id === auth.user?.user_id" @click="openReset(user)"><KeyRound :size="14" /> 重置密码</button><button class="switch-control" :class="{ active: user.status === 1 }" role="switch" :aria-checked="user.status === 1" :disabled="user.id === auth.user?.user_id" @click="toggle(user)"><i></i></button></div></td></tr></tbody></table></div><div v-if="!users.length && !loading" class="empty-state">暂无管理员账号</div></article>

    <div v-if="dialog" class="modal-layer" @mousedown.self="dialog = null"><form class="modal-card" @submit.prevent="save"><div class="modal-heading"><div><p class="eyebrow">{{ dialog === 'create' ? 'NEW ADMIN' : 'RESET PASSWORD' }}</p><h2>{{ dialog === 'create' ? '添加管理员' : `重置 ${target?.username} 的密码` }}</h2></div><button type="button" aria-label="关闭" @click="dialog = null"><X :size="20" /></button></div><template v-if="dialog === 'create'"><label class="field-label" for="user-name">用户名</label><div class="input-shell"><UserRoundCog :size="17" /><input id="user-name" v-model.trim="form.username" required minlength="3" maxlength="50" autocomplete="off" placeholder="3-50 位字母、数字或 ._-" /></div><label class="field-label" for="user-email">邮箱（可选）</label><div class="input-shell"><input id="user-email" v-model.trim="form.email" type="email" maxlength="100" placeholder="admin@example.com" /></div></template><label class="field-label" for="temp-password">临时密码</label><div class="input-shell"><ShieldCheck :size="17" /><input id="temp-password" v-model="form.password" required minlength="12" maxlength="255" autocomplete="new-password" /></div><button type="button" class="text-button generate-button" @click="randomPassword">重新生成随机密码</button><p class="field-help">请在保存前复制并安全传递。系统不会再次显示该密码，用户首次登录后必须修改。</p><div class="modal-actions"><button type="button" class="secondary-button" @click="dialog = null">取消</button><button class="primary-button" type="submit" :disabled="saving">{{ saving ? '正在保存…' : '确认保存' }}</button></div></form></div>
  </section>
</template>
