<script setup lang="ts">
import { computed, onMounted, onBeforeUnmount, ref } from 'vue'
import { useRoute } from 'vue-router'
import { Download, Eye, Filter, RefreshCw, Search, ShieldAlert, X } from '@lucide/vue'
import { apiDownload, apiRequest } from '../api/client'
import WAFStatusView from './WAFStatusView.vue'
import type { AttackIPSummary, AttackLog, PageData } from '../types/api'
import BatchBlockDialog from '../components/BatchBlockDialog.vue'
import { validateIPFilter } from '../utils/ip'

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
const route = useRoute()
const ipMode = ref('exact')
const selectedIPs = ref<string[]>([])
const showBatch = ref(false)
const notice = ref('')
const summary = ref<AttackIPSummary | null>(null)
const summaryError = ref('')
const summaryLoading = ref(false)
let controller: AbortController | null = null
let requestVersion = 0
const pageIPs = computed(() => [...new Set(logs.value.map(log => log.ip))])
const allPageSelected = computed(() => pageIPs.value.length > 0 && pageIPs.value.every(value => selectedIPs.value.includes(value)))

const types = ['CC攻击', 'XSS攻击', 'SQL注入', 'IP黑名单', '海外IP拦截', '穿盾攻击', '验证失败次数过多', '自定义策略', '路径穿越', 'SSRF', 'XXE', '扫描探测']
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
  if (ip.value.trim()) { query.set('ip', ip.value.trim()); query.set('ip_mode', ipMode.value) }
  if (attackType.value) query.set('attack_type', attackType.value)
  if (severity.value) query.set('severity', String(severity.value))
  if (startAt.value) query.set('start_at', new Date(startAt.value).toISOString())
  if (endAt.value) query.set('end_at', new Date(endAt.value).toISOString())
}

async function load(reset = false) {
  controller?.abort()
  const version = ++requestVersion
  const validation = validateFilters()
  if (validation) { error.value = validation; loading.value = false; summaryLoading.value = false; return }
  controller = new AbortController()
  const signal = controller.signal
  if (reset) page.value = 1
  loading.value = true
  error.value = ''
  const query = new URLSearchParams({ page: String(page.value), size: String(size.value) })
  appendFilters(query)
  try {
    summary.value = null; summaryError.value = ''; summaryLoading.value = false
    if (ip.value.trim() && ipMode.value === 'exact') void loadSummary(signal, version)
    const data = await apiRequest<PageData<AttackLog>>(`/attacks?${query}`, { signal })
    if (version !== requestVersion) return
    logs.value = data.list
    total.value = data.total
    if (page.value > totalPages.value) {
      page.value = totalPages.value
      await load()
    }
  } catch (reason) {
    if (signal.aborted || version !== requestVersion) return
    error.value = reason instanceof Error ? reason.message : '攻击事件加载失败'
  } finally {
    if (version === requestVersion) loading.value = false
  }
}

function validateFilters(): string {
  const ipError = validateIPFilter(ip.value.trim(), ipMode.value)
  if (ipError) return ipError
  if ((startAt.value && !Number.isFinite(Date.parse(startAt.value))) || (endAt.value && !Number.isFinite(Date.parse(endAt.value)))) return '请选择有效的开始与结束时间'
  if (startAt.value && endAt.value && Date.parse(startAt.value) > Date.parse(endAt.value)) return '开始时间不能晚于结束时间'
  return ''
}

/** Fetch IP attribution separately; stale results never overwrite a newer query. */
async function loadSummary(signal: AbortSignal, version: number) {
  summaryLoading.value = true
  const query = new URLSearchParams({ ip: ip.value.trim() })
  if (startAt.value) query.set('start_at', new Date(startAt.value).toISOString())
  if (endAt.value) query.set('end_at', new Date(endAt.value).toISOString())
  try {
    const data = await apiRequest<AttackIPSummary>(`/attacks/ip-summary?${query}`, { signal })
    if (version === requestVersion) summary.value = data
  } catch (cause) {
    if (!signal.aborted && version === requestVersion) summaryError.value = cause instanceof Error ? cause.message : 'IP 画像加载失败'
  } finally { if (version === requestVersion) summaryLoading.value = false }
}

function inspectIP(value: string) { ip.value = value; ipMode.value = 'exact'; void load(true) }
function toggleIP(value: string) {
  if (selectedIPs.value.includes(value)) selectedIPs.value = selectedIPs.value.filter(item => item !== value)
  else if (selectedIPs.value.length < 500) selectedIPs.value.push(value)
  else error.value = '最多选择 500 个 IP，请先处理已选地址'
}
function selectPage() {
  if (allPageSelected.value) selectedIPs.value = selectedIPs.value.filter(value => !pageIPs.value.includes(value))
  else {
    const combined = [...new Set([...selectedIPs.value, ...pageIPs.value])]
    if (combined.length > 500) { error.value = '选择本页后将超过 500 个 IP，请先处理已选地址'; return }
    selectedIPs.value = combined
  }
}

async function exportLogs() {
  const validation = validateFilters()
  if (validation) { error.value = validation; return }
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

onMounted(() => { if (typeof route.query.ip === 'string') ip.value = route.query.ip; void load() })
onBeforeUnmount(() => { controller?.abort(); requestVersion++ })
</script>

<template>
  <section class="page-content attack-page">
    <header class="page-header">
      <div><p class="eyebrow">ATTACK INTELLIGENCE</p><h1>攻击事件</h1><p>按五级风险追踪命中规则、来源、处置结果与累计攻击次数。</p></div>
      <div class="header-actions">
        <button class="primary-button" @click="showBatch = true">批量封禁 IP</button>
        <button class="secondary-button" :disabled="exporting || loading" @click="exportLogs"><Download :size="17" /> {{ exporting ? '导出中…' : '导出日志' }}</button>
        <button class="secondary-button" :disabled="loading" @click="load()"><RefreshCw :size="17" :class="{ spinning: loading }" /> 刷新</button>
      </div>
    </header>

    <details class="context-details"><summary>行为检测运行指标</summary><WAFStatusView section="behavior" /></details>
    <div class="severity-strip" aria-label="按严重度筛选">
      <button v-for="option in severityOptions" :key="option.value" :class="[option.className, { active: severity === option.value }]" @click="setSeverity(option.value)">
        <i></i><span>{{ option.label }}</span>
      </button>
    </div>

    <div class="filter-bar attack-filters">
      <label class="filter-field"><span>事件</span><input v-model="eventId" placeholder="事件编号" @keyup.enter="load(true)" /></label>
      <label class="filter-field"><Search :size="17" /><span class="sr-only">来源 IP</span><input v-model="ip" placeholder="IPv4 / IPv6 / 网段" @keyup.enter="load(true)" /></label>
      <label class="filter-field select-field"><span>匹配</span><select v-model="ipMode"><option value="exact">完整 IP</option><option value="prefix">文本前缀</option><option value="cidr">CIDR 网段</option></select></label>
      <label class="filter-field select-field"><Filter :size="17" /><span class="sr-only">攻击类型</span><select v-model="attackType" @change="load(true)"><option value="">全部攻击类型</option><option v-for="type in types" :key="type">{{ type }}</option></select></label>
      <label class="filter-field date-field"><span>开始</span><input v-model="startAt" type="datetime-local" /></label>
      <label class="filter-field date-field"><span>结束</span><input v-model="endAt" type="datetime-local" /></label>
      <button class="primary-button" :disabled="loading" @click="load(true)">查询事件</button>
    </div>

    <p v-if="error" class="inline-alert">{{ error }}</p>
    <p v-if="notice" class="inline-success" role="status">{{ notice }}</p>
    <p v-if="summaryError" class="inline-alert" role="alert">IP 画像：{{ summaryError }}</p>
    <p v-if="summaryLoading" class="field-help" role="status">正在查询 IP 风险画像…</p>
    <article v-if="summary" class="panel ip-summary"><div class="panel-heading"><div><span>IP 风险画像 · {{ summary.ip }}</span><strong>{{ summary.list_status === 'whitelist' ? '当前白名单' : summary.list_status === 'blacklist' ? '当前黑名单' : '尚无有效名单策略' }}</strong></div><button class="secondary-button" @click="selectedIPs = [summary.ip]; showBatch = true">封禁此 IP</button></div><div class="status-metrics"><div><span>累计攻击</span><strong>{{ summary.attack_count.toLocaleString() }}</strong></div><div><span>聚合记录</span><strong>{{ summary.records }}</strong></div><div><span>拦截 / 观察记录</span><strong>{{ summary.blocked_records }} / {{ summary.observed_records }}</strong></div><div><span>最高风险</span><strong>{{ severityMeta(summary.max_severity).label }}</strong></div></div><div class="summary-details"><p>首次 {{ summary.first_seen ? formatTime(summary.first_seen) : '无记录' }} · 最近 {{ summary.last_seen ? formatTime(summary.last_seen) : '无记录' }}</p><p>类型：{{ summary.attack_types.map(item => `${item.attack_type} (${item.count})`).join('、') || '无' }}</p><p>站点：{{ summary.hosts.map(item => `${item.host} (${item.count})`).join('、') || '无' }}</p><p class="field-help">按每日 / 类型聚合记录统计；计数为记录累计次数，非时间窗内逐请求精确计数。</p></div></article>
    <div class="bulk-toolbar"><span>已选 {{ selectedIPs.length }} / 500 个唯一 IP（跨页保留）</span><button class="secondary-button" :disabled="!selectedIPs.length" @click="showBatch = true">封禁已选</button><button class="text-button" :disabled="!selectedIPs.length" @click="selectedIPs = []">清空选择</button></div>
    <article class="panel table-panel attack-table-panel">
      <div class="table-meta"><span>事件列表</span><strong>共 {{ total.toLocaleString() }} 条 · 当前 {{ rangeStart }}–{{ rangeEnd }}</strong></div>
      <div class="table-scroll">
        <table class="attack-table">
          <thead><tr><th><input type="checkbox" :checked="allPageSelected" aria-label="选择本页所有 IP" @change="selectPage" /></th><th>风险</th><th>来源</th><th>事件类型</th><th>请求</th><th>攻击详情</th><th>次数</th><th>时间</th></tr></thead>
          <tbody>
            <tr v-for="log in logs" :key="log.id" :class="`severity-row-${severityMeta(log.severity).className}`">
              <td><input type="checkbox" :checked="selectedIPs.includes(log.ip)" :aria-label="`选择 IP ${log.ip}`" @change="toggleIP(log.ip)" /></td>
              <td><span class="severity-badge" :class="severityMeta(log.severity).className"><i></i>{{ severityMeta(log.severity).label }}</span></td>
              <td><button class="text-button mono source-ip" :aria-label="`检索 ${log.ip} 风险画像`" @click="inspectIP(log.ip)">{{ log.ip }}</button><small>{{ log.ip_location || '未知归属地' }}</small></td>
              <td><span class="event-badge"><ShieldAlert :size="14" />{{ log.attack_type }}</span><small>{{ log.status === 1 ? '已拦截' : '仅记录' }}</small><small v-if="log.event_id" class="event-id" :title="log.event_id">{{ log.event_id }}</small></td>
              <td><span class="method-badge">{{ log.method }}</span><code :title="log.host + log.uri">{{ log.host }}{{ log.uri || '/' }}</code></td>
              <td class="detail-cell"><span :title="log.attack_detail">{{ log.attack_detail || '—' }}</span><button class="packet-button" type="button" :disabled="!log.request_packet" @click="selectedLog = log"><Eye :size="13" />{{ log.request_packet ? '查看报文' : '暂无报文' }}</button></td>
              <td><strong class="attack-count">{{ log.attack_count.toLocaleString() }}</strong></td>
              <td class="nowrap event-time">{{ formatTime(log.created_at) }}</td>
            </tr>
            <tr v-if="loading"><td colspan="8"><div class="empty-state" role="status">正在查询攻击记录…</div></td></tr>
            <tr v-if="!logs.length && !loading"><td colspan="8"><div class="empty-state">当前筛选条件下没有攻击事件</div></td></tr>
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
    <BatchBlockDialog v-if="showBatch" :ips="selectedIPs" @close="showBatch = false" @completed="result => { notice = `本机封禁 ${result.blocked} 个，白名单跳过 ${result.skipped_whitelist} 个`; selectedIPs = []; load() }" />
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
