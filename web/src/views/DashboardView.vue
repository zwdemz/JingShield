<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import * as echarts from 'echarts/core'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { LineChart } from 'echarts/charts'
import { CanvasRenderer } from 'echarts/renderers'
import { Activity, Ban, BellRing, Cpu, Database, Gauge, Globe2, HardDrive, MemoryStick, RefreshCw, Settings2, ShieldCheck, TrendingUp, UsersRound, Waypoints, X } from '@lucide/vue'
import { apiRequest, jsonBody } from '../api/client'
import type { AlertThresholds, DashboardStats, ProtectionStatus, SystemResources, TopIP, TrendPoint } from '../types/api'

echarts.use([GridComponent, TooltipComponent, LineChart, CanvasRenderer])

const loading = ref(true)
const error = ref('')
const stats = ref<DashboardStats>({ total_requests: 0, total_ips: 0, blocked_requests: 0, blacklist_ips: 0, whitelist_ips: 0 })
const trend = ref<TrendPoint[]>([])
const topIPs = ref<TopIP[]>([])
const status = ref<ProtectionStatus>({})
const chartEl = ref<HTMLDivElement | null>(null)
const resources = ref<SystemResources | null>(null)
const showThresholds = ref(false)
const savingThresholds = ref(false)
const thresholdForm = ref<AlertThresholds>({ cpu_percent: 80, memory_percent: 85, disk_percent: 85, log_size_mb: 512, request_rate: 600 })
let chart: echarts.ECharts | null = null
let resourceTimer: number | null = null

const blockRate = computed(() => stats.value.total_requests ? Math.min(100, stats.value.blocked_requests / stats.value.total_requests * 100) : 0)
const statCards = computed(() => [
  { label: '今日请求', value: stats.value.total_requests, note: '今日已进入防护链', icon: Waypoints, tone: 'cyan' },
  { label: '今日访客 IP', value: stats.value.total_ips, note: '今日独立访问来源', icon: UsersRound, tone: 'blue' },
  { label: '今日拦截', value: stats.value.blocked_requests, note: `今日拦截率 ${blockRate.value.toFixed(1)}%`, icon: Ban, tone: 'red' },
  { label: '黑名单 IP', value: stats.value.blacklist_ips, note: `${stats.value.whitelist_ips} 个白名单`, icon: Globe2, tone: 'amber' },
])
const modules = computed(() => [
  ['CC 防护', status.value.cc_protection_status],
  ['XSS 检测', status.value.xss_protection_status],
  ['SQL 注入检测', status.value.sql_protection_status],
  ['海外 IP 策略', status.value.oversea_ip_status],
] as const)
const resourceItems = computed(() => resources.value ? [
  { key: 'cpu', label: 'CPU', value: resources.value.cpu_percent, display: `${resources.value.cpu_percent.toFixed(1)}%`, threshold: resources.value.thresholds.cpu_percent, icon: Cpu, tone: 'cyan' },
  { key: 'memory', label: '内存', value: resources.value.memory_percent, display: `${resources.value.memory_percent.toFixed(1)}%`, threshold: resources.value.thresholds.memory_percent, icon: MemoryStick, tone: 'blue' },
  { key: 'disk', label: '磁盘', value: resources.value.disk_percent, display: `${resources.value.disk_percent.toFixed(1)}%`, threshold: resources.value.thresholds.disk_percent, icon: HardDrive, tone: 'amber' },
  { key: 'log', label: '日志占用', value: resources.value.log_size_bytes / 1024 / 1024, display: formatBytes(resources.value.log_size_bytes), threshold: resources.value.thresholds.log_size_mb, icon: Database, tone: 'purple' },
  { key: 'rate', label: '业务速率', value: resources.value.request_rate, display: `${resources.value.request_rate}/min`, threshold: resources.value.thresholds.request_rate, icon: Activity, tone: 'red' },
] : [])

function renderChart() {
  if (!chartEl.value) return
  chart ||= echarts.init(chartEl.value)
  const labels = trend.value.map((item) => `${item.hour}:00`)
  const values = trend.value.map((item) => item.count)
  chart.setOption({
    animationDuration: 650,
    grid: { left: 12, right: 16, top: 24, bottom: 8, containLabel: true },
    tooltip: { trigger: 'axis', backgroundColor: '#111d2f', borderColor: '#263a53', textStyle: { color: '#e6edf7' } },
    xAxis: { type: 'category', boundaryGap: false, data: labels, axisLine: { lineStyle: { color: '#2a3c54' } }, axisLabel: { color: '#8493a8' } },
    yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#1d2b3d' } }, axisLabel: { color: '#8493a8' } },
    series: [{ type: 'line', smooth: 0.35, showSymbol: false, data: values, lineStyle: { width: 3, color: '#36e0c5' }, areaStyle: { color: 'rgba(54,224,197,.10)' } }],
  })
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [statsData, trendData, topData, statusData, resourceData] = await Promise.all([
      apiRequest<DashboardStats>('/dashboard/stats'),
      apiRequest<{ trend: TrendPoint[] }>('/dashboard/trend'),
      apiRequest<TopIP[]>('/dashboard/top-ips?limit=6'),
      apiRequest<ProtectionStatus>('/system/status'),
      apiRequest<SystemResources>('/system/resources'),
    ])
    stats.value = statsData
    trend.value = trendData.trend
    topIPs.value = topData
    status.value = statusData
    resources.value = resourceData
    thresholdForm.value = { ...resourceData.thresholds }
    await nextTick()
    renderChart()
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '加载安全态势失败'
  } finally {
    loading.value = false
  }
}

async function loadResources() {
  try { resources.value = await apiRequest<SystemResources>('/system/resources') }
  catch (reason) { error.value = reason instanceof Error ? reason.message : '本机资源加载失败' }
}

function openThresholds() {
  if (resources.value) thresholdForm.value = { ...resources.value.thresholds }
  showThresholds.value = true
}

async function saveThresholds() {
  savingThresholds.value = true
  try {
    await apiRequest<null>('/system/alert-thresholds', { method: 'PUT', ...jsonBody(thresholdForm.value) })
    showThresholds.value = false
    await loadResources()
  } catch (reason) { error.value = reason instanceof Error ? reason.message : '阈值保存失败' }
  finally { savingThresholds.value = false }
}

function resourcePercent(key: string, value: number, threshold: number) {
  if (key === 'log' || key === 'rate') return Math.min(100, value / Math.max(1, threshold) * 100)
  return Math.min(100, value)
}
function formatBytes(value: number) {
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`
  return `${(value / 1024 / 1024 / 1024).toFixed(1)} GB`
}
function formatUptime(seconds: number) { const days = Math.floor(seconds / 86400); const hours = Math.floor(seconds % 86400 / 3600); return `${days}天 ${hours}小时` }

function resizeChart() { chart?.resize() }
onMounted(() => { load(); resourceTimer = window.setInterval(loadResources, 15000); window.addEventListener('resize', resizeChart) })
onBeforeUnmount(() => { if (resourceTimer) window.clearInterval(resourceTimer); window.removeEventListener('resize', resizeChart); chart?.dispose() })
</script>

<template>
  <section class="page-content">
    <header class="page-header">
      <div><p class="eyebrow">SECURITY OVERVIEW</p><h1>今日安全态势</h1><p>聚合节点流量、攻击事件与防护策略运行情况。</p></div>
      <button class="secondary-button" :disabled="loading" @click="load"><RefreshCw :size="17" :class="{ spinning: loading }" /> 刷新数据</button>
    </header>
    <p v-if="error" class="inline-alert">{{ error }}</p>

    <div class="stat-grid">
      <article v-for="card in statCards" :key="card.label" class="stat-card" :class="`tone-${card.tone}`">
        <div class="stat-icon"><component :is="card.icon" :size="21" /></div>
        <span>{{ card.label }}</span><strong>{{ card.value.toLocaleString() }}</strong><small>{{ card.note }}</small>
      </article>
    </div>

    <div v-if="resources" class="environment-grid">
      <article class="panel resource-panel">
        <div class="panel-heading"><div><span>本机运行环境</span><strong>{{ resources.hostname }} · {{ resources.platform }} · 已运行 {{ formatUptime(resources.uptime_seconds) }}</strong></div><button class="resource-settings" @click="openThresholds"><Settings2 :size="16" /> 告警阈值</button></div>
        <div class="resource-list"><div v-for="item in resourceItems" :key="item.key" class="resource-item"><div class="resource-title"><span :class="`tone-${item.tone}`"><component :is="item.icon" :size="16" /></span><div><strong>{{ item.label }}</strong><small>阈值 {{ item.threshold }}{{ item.key === 'log' ? ' MB' : item.key === 'rate' ? '/min' : '%' }}</small></div><b>{{ item.display }}</b></div><div class="resource-track"><i :class="{ warning: item.value >= item.threshold }" :style="{ width: `${resourcePercent(item.key, item.value, item.threshold)}%` }"></i><em v-if="item.key !== 'log' && item.key !== 'rate'" :style="{ left: `${item.threshold}%` }"></em></div></div></div>
      </article>
      <article class="panel alert-panel">
        <div class="panel-heading"><div><span>资源告警</span><strong>15 秒自动刷新</strong></div><BellRing :size="20" /></div>
        <div v-if="!resources.alerts.length" class="resource-healthy"><ShieldCheck :size="30" /><strong>节点资源正常</strong><span>所有指标均低于当前阈值</span></div>
        <ul v-else class="alert-list"><li v-for="alert in resources.alerts" :key="alert.resource" :class="alert.level"><i></i><div><strong>{{ alert.message }}</strong><span>{{ alert.current.toFixed(1) }} {{ alert.unit }} / 阈值 {{ alert.threshold }} {{ alert.unit }}</span></div></li></ul>
      </article>
    </div>

    <div class="dashboard-grid">
      <article class="panel trend-panel">
        <div class="panel-heading"><div><span>攻击趋势</span><strong>今日逐小时</strong></div><TrendingUp :size="21" /></div>
        <div v-if="loading" class="chart-skeleton"></div>
        <div v-show="!loading" ref="chartEl" class="trend-chart" aria-label="今日逐小时攻击趋势图"></div>
      </article>
      <article class="panel protection-panel">
        <div class="panel-heading"><div><span>防护矩阵</span><strong>核心引擎状态</strong></div><ShieldCheck :size="21" /></div>
        <div class="protection-score"><strong>{{ status.system_status ? 'ON' : 'OFF' }}</strong><span>系统总开关</span></div>
        <ul class="module-list">
          <li v-for="module in modules" :key="module[0]"><span>{{ module[0] }}</span><b :class="{ active: module[1] === 1 }">{{ module[1] === 1 ? '已启用' : '未启用' }}</b></li>
        </ul>
      </article>
      <article class="panel top-ip-panel">
        <div class="panel-heading"><div><span>高风险来源</span><strong>今日攻击 IP TOP 6</strong></div><Globe2 :size="21" /></div>
        <div v-if="!topIPs.length && !loading" class="empty-state">暂无攻击来源数据</div>
        <ol v-else class="rank-list">
          <li v-for="(item, index) in topIPs" :key="item.ip">
            <i>{{ String(index + 1).padStart(2, '0') }}</i><span>{{ item.ip }}</span>
            <div><em :style="{ width: `${Math.max(8, item.count / Math.max(...topIPs.map((ip) => ip.count)) * 100)}%` }"></em></div><strong>{{ item.count }}</strong>
          </li>
        </ol>
      </article>
    </div>

    <div v-if="showThresholds" class="modal-layer" @mousedown.self="showThresholds = false"><form class="modal-card threshold-modal" @submit.prevent="saveThresholds"><div class="modal-heading"><div><p class="eyebrow">RESOURCE ALERTS</p><h2>本机资源告警阈值</h2></div><button type="button" aria-label="关闭" @click="showThresholds = false"><X :size="20" /></button></div><p class="threshold-note"><Gauge :size="16" /> 业务速率默认阈值为 600 请求/分钟（10 RPS）；它只产生运维告警，不改变 CC 防护规则。</p><div class="threshold-fields"><label><span>CPU 使用率<small>1-100%</small></span><input v-model.number="thresholdForm.cpu_percent" type="number" min="1" max="100" required /></label><label><span>内存使用率<small>1-100%</small></span><input v-model.number="thresholdForm.memory_percent" type="number" min="1" max="100" required /></label><label><span>磁盘使用率<small>1-100%</small></span><input v-model.number="thresholdForm.disk_percent" type="number" min="1" max="100" required /></label><label><span>日志目录大小<small>MB</small></span><input v-model.number="thresholdForm.log_size_mb" type="number" min="1" max="1048576" required /></label><label><span>业务请求速率<small>请求/分钟</small></span><input v-model.number="thresholdForm.request_rate" type="number" min="1" max="1000000" required /></label></div><div class="modal-actions"><button type="button" class="secondary-button" @click="showThresholds = false">取消</button><button class="primary-button" type="submit" :disabled="savingThresholds">{{ savingThresholds ? '保存中…' : '应用阈值' }}</button></div></form></div>
  </section>
</template>
