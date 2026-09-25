<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import * as echarts from 'echarts/core'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { LineChart } from 'echarts/charts'
import { CanvasRenderer } from 'echarts/renderers'
import { Ban, Globe2, RefreshCw, TrendingUp, UsersRound, Waypoints } from '@lucide/vue'
import { apiRequest } from '../api/client'
import type { DashboardStats, ProtectionStatus, TopIP, TrendPoint } from '../types/api'

echarts.use([GridComponent, TooltipComponent, LineChart, CanvasRenderer])

const loading = ref(true)
const error = ref('')
const stats = ref<DashboardStats>({ total_requests: 0, total_ips: 0, blocked_requests: 0, blacklist_ips: 0, whitelist_ips: 0 })
const trend = ref<TrendPoint[]>([])
const topIPs = ref<TopIP[]>([])
const status = ref<ProtectionStatus>({})
const chartEl = ref<HTMLDivElement | null>(null)
let chart: echarts.ECharts | null = null

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
  let chartReady = false
  try {
    const [statsData, trendData, topData, statusData] = await Promise.all([
      apiRequest<DashboardStats>('/dashboard/stats'),
      apiRequest<{ trend: TrendPoint[] }>('/dashboard/trend'),
      apiRequest<TopIP[]>('/dashboard/top-ips?limit=6'),
      apiRequest<ProtectionStatus>('/system/status'),
    ])
    stats.value = statsData
    trend.value = trendData.trend
    topIPs.value = topData
    status.value = statusData
    chartReady = true
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '加载安全态势失败'
  } finally {
    loading.value = false
  }
  if (chartReady) { await nextTick(); renderChart() }
}

function resizeChart() { chart?.resize() }
onMounted(() => { load(); window.addEventListener('resize', resizeChart) })
onBeforeUnmount(() => { window.removeEventListener('resize', resizeChart); chart?.dispose() })
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

    <div class="dashboard-grid">
      <article class="panel trend-panel">
        <div class="panel-heading"><div><span>攻击趋势</span><strong>今日逐小时</strong></div><TrendingUp :size="21" /></div>
        <div v-if="loading" class="chart-skeleton"></div>
        <div v-show="!loading" ref="chartEl" class="trend-chart" aria-label="今日逐小时攻击趋势图"></div>
      </article>
      <article class="panel protection-panel">
        <div class="panel-heading"><div><span>防护矩阵</span><strong>核心引擎状态</strong></div><RouterLink class="secondary-button" :to="{ name: 'settings' }">配置引擎</RouterLink></div>
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
            <i>{{ String(index + 1).padStart(2, '0') }}</i><RouterLink :to="{ name: 'attacks', query: { ip: item.ip } }" class="mono">{{ item.ip }}</RouterLink>
            <div><em :style="{ width: `${Math.max(8, item.count / Math.max(...topIPs.map((ip) => ip.count)) * 100)}%` }"></em></div><strong>{{ item.count }}</strong>
          </li>
        </ol>
      </article>
    </div>

  </section>
</template>
