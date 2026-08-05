<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { Plus, RefreshCw, Search, ShieldCheck, ShieldX, Trash2, X } from '@lucide/vue'
import { APIError, apiRequest, jsonBody } from '../api/client'
import type { IPListItem, PageData } from '../types/api'

const loading = ref(false)
const saving = ref(false)
const error = ref('')
const notice = ref('')
const items = ref<IPListItem[]>([])
const total = ref(0)
const page = ref(1)
const size = 10
const filterType = ref(0)
const filterIP = ref('')
const showForm = ref(false)
const form = reactive({ ip: '', type: 2, reason: '', expire_seconds: 3600 })
const typeNames: Record<number, string> = { 1: '白名单', 2: '永久黑名单', 3: '临时黑名单' }

async function load(reset = false) {
  if (reset) page.value = 1
  loading.value = true
  const query = new URLSearchParams({ page: String(page.value), size: String(size), type: String(filterType.value) })
  if (filterIP.value.trim()) query.set('ip', filterIP.value.trim())
  try { const data = await apiRequest<PageData<IPListItem>>(`/ip-list?${query}`); items.value = data.list; total.value = data.total; error.value = '' }
  catch (reason) { error.value = reason instanceof Error ? reason.message : 'IP 名单加载失败' }
  finally { loading.value = false }
}

async function addItem() {
  saving.value = true
  error.value = ''
  try {
    await apiRequest<null>('/ip-list', { method: 'POST', ...jsonBody(form) })
    notice.value = `${form.ip} 已加入${typeNames[form.type]}`
    Object.assign(form, { ip: '', type: 2, reason: '', expire_seconds: 3600 })
    showForm.value = false
    await load(true)
  } catch (reason) { error.value = reason instanceof APIError ? reason.message : '新增失败' }
  finally { saving.value = false }
}

async function remove(item: IPListItem) {
  if (!window.confirm(`确认从${typeNames[item.type]}删除 ${item.ip}？`)) return
  try { await apiRequest<null>(`/ip-list/${item.id}`, { method: 'DELETE' }); notice.value = `${item.ip} 已删除`; await load() }
  catch (reason) { error.value = reason instanceof Error ? reason.message : '删除失败' }
}

function formatTime(value: string | null) { return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '永久' }
onMounted(() => load())
</script>

<template>
  <section class="page-content">
    <header class="page-header"><div><p class="eyebrow">IP POLICY</p><h1>IP 策略</h1><p>统一管理精确 IP、CIDR 网段与 IPv4 通配符规则。</p></div><div class="header-actions"><button class="secondary-button" :disabled="loading" @click="load()"><RefreshCw :size="17" :class="{ spinning: loading }" /> 刷新</button><button class="primary-button" @click="showForm = true"><Plus :size="17" /> 新增规则</button></div></header>
    <p v-if="error" class="inline-alert">{{ error }}</p><p v-if="notice" class="inline-success">{{ notice }}</p>
    <div class="filter-bar"><div class="filter-field"><Search :size="17" /><input v-model="filterIP" placeholder="IP / CIDR / 通配符" @keyup.enter="load(true)" /></div><div class="segmented"><button v-for="option in [{v:0,l:'全部'},{v:1,l:'白名单'},{v:2,l:'黑名单'},{v:3,l:'临时'}]" :key="option.v" :class="{ active: filterType === option.v }" @click="filterType = option.v; load(true)">{{ option.l }}</button></div></div>
    <article class="panel table-panel">
      <div class="table-meta"><span>策略清单</span><strong>{{ total }} 条规则</strong></div>
      <div class="table-scroll"><table><thead><tr><th>规则</th><th>类型</th><th>原因</th><th>有效期</th><th>创建时间</th><th></th></tr></thead><tbody>
        <tr v-for="item in items" :key="item.id"><td><strong class="mono">{{ item.ip }}</strong></td><td><span class="policy-badge" :class="`type-${item.type}`"><ShieldCheck v-if="item.type === 1" :size="14" /><ShieldX v-else :size="14" />{{ typeNames[item.type] }}</span></td><td>{{ item.reason || '未填写' }}</td><td>{{ formatTime(item.expire_time) }}</td><td>{{ formatTime(item.created_at) }}</td><td><button class="danger-icon" title="删除规则" @click="remove(item)"><Trash2 :size="17" /></button></td></tr>
        <tr v-if="!items.length && !loading"><td colspan="6"><div class="empty-state">暂无 IP 策略</div></td></tr>
      </tbody></table></div>
      <div class="pagination"><button :disabled="page <= 1 || loading" @click="page--; load()">上一页</button><span>第 {{ page }} 页</span><button :disabled="page * size >= total || loading" @click="page++; load()">下一页</button></div>
    </article>

    <div v-if="showForm" class="modal-layer" @mousedown.self="showForm = false">
      <form class="modal-card" @submit.prevent="addItem">
        <div class="modal-heading"><div><p class="eyebrow">NEW POLICY</p><h2>新增 IP 规则</h2></div><button type="button" aria-label="关闭" @click="showForm = false"><X :size="20" /></button></div>
        <label class="field-label" for="rule-ip">IP 规则</label><div class="input-shell"><input id="rule-ip" v-model="form.ip" required placeholder="例如 192.168.1.10 或 10.0.0.0/8" /></div>
        <label class="field-label" for="rule-type">策略类型</label><div class="input-shell"><select id="rule-type" v-model="form.type"><option :value="1">白名单</option><option :value="2">永久黑名单</option><option :value="3">临时黑名单</option></select></div>
        <label class="field-label" for="rule-reason">加入原因</label><div class="input-shell"><input id="rule-reason" v-model="form.reason" maxlength="255" placeholder="选填，建议记录来源" /></div>
        <template v-if="form.type === 3"><label class="field-label" for="rule-expire">有效期（秒）</label><div class="input-shell"><input id="rule-expire" v-model.number="form.expire_seconds" type="number" min="1" max="31536000" required /></div></template>
        <div class="modal-actions"><button type="button" class="secondary-button" @click="showForm = false">取消</button><button class="primary-button" type="submit" :disabled="saving">{{ saving ? '正在保存…' : '保存规则' }}</button></div>
      </form>
    </div>
  </section>
</template>
