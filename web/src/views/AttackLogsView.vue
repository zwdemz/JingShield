<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Download, Eye, Filter, RefreshCw, Search, ShieldAlert, X } from '@lucide/vue'
import { apiDownload, apiRequest } from '../api/client'
import type { AttackLog, PageData } from '../types/api'

const loading = ref(false)
const exporting = ref(false)
const error = ref('')
const logs = ref<AttackLog[]>([])
const total = ref(0)
const page = ref(1)
const size = ref(20)
const ip = ref('')
const eventId = ref('')
const attackType = ref('')
const severity = ref(0)
const startAt = ref('')
const endAt = ref('')
const selectedLog = ref<AttackLog | null>(null)

const types = ['CC攻击', 'XSS攻击', 'SQL注入', 'IP黑名单', '海外IP拦截', '穿盾攻击', '验证失败次数过多', '自定义策略']
const severityOptions = [
  { value: 0, label: '全部等级', className: 'all' },
  { value: 5, label: '严重', className: 'critical' },
  { value: 4, label: '高危', className: 'high' },
  { value: 3, label: '中危', className: 'medium' },
  { value: 2, label: '低危', className: 'low' },
  { value: 1, label: '信息', className: 'info' },
]

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / size.value)))
const rangeStart = computed(() => total.value ? (page.value - 1) * size.value + 1 : 0)
const rangeEnd = computed(() => Math.min(page.value * size.value, total.value))
const visiblePages = computed(() => {
  const result: number[] = []
  const start = Math.max(1, Math.min(page.value - 2, totalPages.value - 4))
  const end = Math.min(totalPages.value, start + 4)
  for (let value = Math.max(1, end - 4); value <= end; value++) result.push(value)
  return result
})

function appendFilters(query: URLSearchParams) {
  if (eventId.value.trim()) query.set('event_id', eventId.value.trim())
  if (ip.value.trim()) query.set('ip', ip.value.trim())
  if (attackType.value) query.set('attack_type', attackType.value)
  if (severity.value) query.set('severity', String(severity.value))
  if (startAt.value) query.set('start_at', new Date(startAt.value).toISOString())
  if (endAt.value) query.set('end_at', new Date(endAt.value).toISOString())
}

async function load(reset = false) {
  if (reset) page.value = 1
  loading.value = true
  error.value = ''
  const query = new URLSearchParams({ page: String(page.value), size: String(size.value) })
  appendFilters(query)
  try {
    const data = await apiRequest<PageData<AttackLog>>(`/attacks?${query}`)
    logs.value = data.list
    total.value = data.total
    if (page.value > totalPages.value) {
      page.value = totalPages.value
      await load()
    }
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '攻击事件加载失败'
  } finally {
    loading.value = false
  }
}

async function exportLogs() {
  exporting.value = true
  error.value = ''
  const query = new URLSearchParams()
  appendFilters(query)
  try {
    const { blob, filename } = await apiDownload(`/attacks/export?${query}`)
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '攻击事件导出失败'
  } finally {
    exporting.value = false
  }
}

function setSeverity(value: number) {
  severity.value = value
  load(true)
}

function goToPage(value: number) {
  if (value === page.value || value < 1 || value > totalPages.value) return
  page.value = value
  load()
}

function severityMeta(value: number) {
  return severityOptions.find(option => option.value === value) || severityOptions[5]
}

function formatTime(value: string) {
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

onMounted(() => load())
</script>

<template>
  <section class="page-content attack-page">
    <header class="page-header">
      <div><p class="eyebrow">ATTACK INTELLIGENCE</p><h1>攻击事件</h1><p>按五级风险追踪命中规则、来源、处置结果与累计攻击次数。</p></div>
      <div class="header-actions">
        <button class="secondary-button" :disabled="exporting || loading" @click="exportLogs"><Download :size="17" /> {{ exporting ? '导出中…' : '导出日志' }}</button>
        <button class="secondary-button" :disabled="loading" @click="load()"><RefreshCw :size="17" :class="{ spinning: loading }" /> 刷新</button>
      </div>
    </header>

    <div class="severity-strip" aria-label="按严重度筛选">
      <button v-for="option in severityOptions" :key="option.value" :class="[option.className, { active: severity === option.value }]" @click="setSeverity(option.value)">
        <i></i><span>{{ option.label }}</span>
      </button>
    </div>

    <div class="filter-bar attack-filters">
      <div class="filter-field"><Search :size="17" /><input v-model="eventId" placeholder="事件编号精确查询" @keyup.enter="load(true)" /></div>
      <div class="filter-field"><Search :size="17" /><input v-model="ip" placeholder="来源 IP 精确查询" @keyup.enter="load(true)" /></div>
      <div class="filter-field select-field"><Filter :size="17" /><select v-model="attackType" @change="load(true)"><option value="">全部攻击类型</option><option v-for="type in types" :key="type">{{ type }}</option></select></div>
      <label class="filter-field date-field"><span>开始</span><input v-model="startAt" type="datetime-local" /></label>
      <label class="filter-field date-field"><span>结束</span><input v-model="endAt" type="datetime-local" /></label>
      <button class="primary-button" :disabled="loading" @click="load(true)">查询事件</button>
    </div>

    <p v-if="error" class="inline-alert">{{ error }}</p>
    <article class="panel table-panel attack-table-panel">
      <div class="table-meta"><span>事件列表</span><strong>共 {{ total.toLocaleString() }} 条 · 当前 {{ rangeStart }}–{{ rangeEnd }}</strong></div>
      <div class="table-scroll">
        <table class="attack-table">
          <thead><tr><th>风险</th><th>来源</th><th>事件类型</th><th>请求</th><th>攻击详情</th><th>次数</th><th>时间</th></tr></thead>
          <tbody>
            <tr v-for="log in logs" :key="log.id" :class="`severity-row-${severityMeta(log.severity).className}`">
              <td><span class="severity-badge" :class="severityMeta(log.severity).className"><i></i>{{ severityMeta(log.severity).label }}</span></td>
              <td><strong class="mono source-ip">{{ log.ip }}</strong><small>{{ log.ip_location || '未知归属地' }}</small></td>
              <td><span class="event-badge"><ShieldAlert :size="14" />{{ log.attack_type }}</span><small>{{ log.status === 1 ? '已拦截' : '仅记录' }}</small><small v-if="log.event_id" class="event-id" :title="log.event_id">{{ log.event_id }}</small></td>
              <td><span class="method-badge">{{ log.method }}</span><code :title="log.host + log.uri">{{ log.host }}{{ log.uri || '/' }}</code></td>
              <td class="detail-cell"><span :title="log.attack_detail">{{ log.attack_detail || '—' }}</span><button class="packet-button" type="button" :disabled="!log.request_packet" @click="selectedLog = log"><Eye :size="13" />{{ log.request_packet ? '查看报文' : '暂无报文' }}</button></td>
              <td><strong class="attack-count">{{ log.attack_count.toLocaleString() }}</strong></td>
              <td class="nowrap event-time">{{ formatTime(log.created_at) }}</td>
            </tr>
            <tr v-if="!logs.length && !loading"><td colspan="7"><div class="empty-state">当前筛选条件下没有攻击事件</div></td></tr>
          </tbody>
        </table>
      </div>
      <div class="pagination attack-pagination">
        <label>每页 <select v-model.number="size" @change="load(true)"><option :value="20">20</option><option :value="50">50</option><option :value="100">100</option></select> 条</label>
        <button :disabled="page <= 1 || loading" @click="goToPage(page - 1)">上一页</button>
        <button v-for="value in visiblePages" :key="value" class="page-number" :class="{ active: page === value }" :disabled="loading" @click="goToPage(value)">{{ value }}</button>
        <button :disabled="page >= totalPages || loading" @click="goToPage(page + 1)">下一页</button>
        <span>共 {{ totalPages.toLocaleString() }} 页</span>
      </div>
    </article>
    <div v-if="selectedLog" class="modal-layer" @mousedown.self="selectedLog = null">
      <article class="modal-card packet-modal">
        <div class="modal-heading"><div><p class="eyebrow">REQUEST EVIDENCE</p><h2>攻击请求报文</h2></div><button type="button" aria-label="关闭" @click="selectedLog = null"><X :size="20" /></button></div>
        <div class="packet-meta"><span>{{ selectedLog.attack_type }}</span><strong>{{ selectedLog.ip }}</strong><code>{{ selectedLog.method }} {{ selectedLog.host }}{{ selectedLog.uri }}</code><time>{{ formatTime(selectedLog.created_at) }}</time></div>
        <p v-if="selectedLog.event_id" class="packet-event-id">事件编号 <strong>{{ selectedLog.event_id }}</strong></p>
        <p class="field-help">Authorization、Cookie、密码、Token、API Key 等敏感值已自动脱敏；超长报文会截断。</p>
        <pre class="request-packet">{{ selectedLog.request_packet }}</pre>
      </article>
    </div>
  </section>
</template>
