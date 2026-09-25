<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { Activity, BellRing, Cpu, Database, Gauge, HardDrive, MemoryStick, RefreshCw, Settings2, ShieldCheck, X } from '@lucide/vue'
import { apiRequest, jsonBody } from '../api/client'
import WAFStatusView from './WAFStatusView.vue'
import type { AlertThresholds, SystemResources } from '../types/api'

const resources = ref<SystemResources | null>(null)
const loading = ref(false)
const saving = ref(false)
const error = ref('')
const showThresholds = ref(false)
const thresholdForm = ref<AlertThresholds>({ cpu_percent: 80, memory_percent: 85, disk_percent: 85, log_size_mb: 512, request_rate: 600 })
let timer: ReturnType<typeof setInterval> | undefined

const resourceItems = computed(() => resources.value ? [
  { key: 'cpu', label: 'CPU', value: resources.value.cpu_percent, display: `${resources.value.cpu_percent.toFixed(1)}%`, threshold: resources.value.thresholds.cpu_percent, icon: Cpu, tone: 'cyan' },
  { key: 'memory', label: '内存', value: resources.value.memory_percent, display: `${resources.value.memory_percent.toFixed(1)}%`, threshold: resources.value.thresholds.memory_percent, icon: MemoryStick, tone: 'blue' },
  { key: 'disk', label: '磁盘', value: resources.value.disk_percent, display: `${resources.value.disk_percent.toFixed(1)}%`, threshold: resources.value.thresholds.disk_percent, icon: HardDrive, tone: 'amber' },
  { key: 'log', label: '日志占用', value: resources.value.log_size_bytes / 1024 / 1024, display: formatBytes(resources.value.log_size_bytes), threshold: resources.value.thresholds.log_size_mb, icon: Database, tone: 'purple' },
  { key: 'rate', label: '业务速率', value: resources.value.request_rate, display: `${resources.value.request_rate}/min`, threshold: resources.value.thresholds.request_rate, icon: Activity, tone: 'red' },
] : [])

/** Refresh host resources without discarding an open threshold draft. */
async function load() {
  if (loading.value) return
  loading.value = true
  try {
    const snapshot = await apiRequest<SystemResources>('/system/resources')
    resources.value = snapshot
    if (!showThresholds.value) thresholdForm.value = { ...snapshot.thresholds }
    error.value = ''
  } catch (cause) { error.value = cause instanceof Error ? cause.message : '本机资源加载失败' }
  finally { loading.value = false }
}
function openThresholds() {
  if (resources.value) thresholdForm.value = { ...resources.value.thresholds }
  showThresholds.value = true
}
async function saveThresholds() {
  if (saving.value) return
  saving.value = true
  try {
    await apiRequest('/system/alert-thresholds', { method: 'PUT', ...jsonBody(thresholdForm.value) })
    showThresholds.value = false
    await load()
  } catch (cause) { error.value = cause instanceof Error ? cause.message : '阈值保存失败' }
  finally { saving.value = false }
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
function formatUptime(seconds: number) {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor(seconds % 86400 / 3600)
  return `${days}天 ${hours}小时`
}
onMounted(() => { void load(); timer = setInterval(() => { if (!document.hidden) void load() }, 15000) })
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
</script>

<template>
  <section class="page-content system-status-page">
    <header class="page-header"><div><p class="eyebrow">SYSTEM HEALTH</p><h1>系统状态</h1><p>本机资源、运行告警与 WAF 服务概况。</p></div><button class="secondary-button" :disabled="loading" @click="load"><RefreshCw :size="17" :class="{ spinning: loading }" />刷新资源</button></header>
    <p v-if="error" class="inline-alert" role="alert">{{ error }}</p>
    <p v-if="loading && !resources" class="empty-state" role="status">正在读取本机运行环境…</p>
    <div v-if="resources" class="environment-grid">
      <article class="panel resource-panel">
        <div class="panel-heading"><div><span>本机运行环境</span><strong>{{ resources.hostname }} · {{ resources.platform }} · 已运行 {{ formatUptime(resources.uptime_seconds) }}</strong></div><button class="resource-settings" @click="openThresholds"><Settings2 :size="16" />告警阈值</button></div>
        <div class="resource-list"><div v-for="item in resourceItems" :key="item.key" class="resource-item"><div class="resource-title"><span :class="`tone-${item.tone}`"><component :is="item.icon" :size="16" /></span><div><strong>{{ item.label }}</strong><small>阈值 {{ item.threshold }}{{ item.key === 'log' ? ' MB' : item.key === 'rate' ? '/min' : '%' }}</small></div><b>{{ item.display }}</b></div><div class="resource-track"><i :class="{ warning: item.value >= item.threshold }" :style="{ width: `${resourcePercent(item.key, item.value, item.threshold)}%` }"></i><em v-if="item.key !== 'log' && item.key !== 'rate'" :style="{ left: `${item.threshold}%` }"></em></div></div></div>
      </article>
      <article class="panel alert-panel">
        <div class="panel-heading"><div><span>资源告警</span><strong>15 秒自动刷新</strong></div><BellRing :size="20" /></div>
        <div v-if="!resources.alerts.length" class="resource-healthy"><ShieldCheck :size="30" /><strong>节点资源正常</strong><span>所有指标均低于当前阈值</span></div>
        <ul v-else class="alert-list"><li v-for="alert in resources.alerts" :key="alert.resource" :class="alert.level"><i></i><div><strong>{{ alert.message }}</strong><span>{{ alert.current.toFixed(1) }} {{ alert.unit }} / 阈值 {{ alert.threshold }} {{ alert.unit }}</span></div></li></ul>
      </article>
    </div>
    <WAFStatusView section="system" />
    <div v-if="showThresholds" class="modal-layer" @mousedown.self="showThresholds = false"><form class="modal-card threshold-modal" @submit.prevent="saveThresholds"><div class="modal-heading"><div><p class="eyebrow">RESOURCE ALERTS</p><h2>本机资源告警阈值</h2></div><button type="button" aria-label="关闭" @click="showThresholds = false"><X :size="20" /></button></div><p class="threshold-note"><Gauge :size="16" />业务速率默认阈值为 600 请求/分钟（10 RPS）；它只产生运维告警，不改变 CC 防护规则。</p><div class="threshold-fields"><label><span>CPU 使用率<small>1-100%</small></span><input v-model.number="thresholdForm.cpu_percent" type="number" min="1" max="100" required /></label><label><span>内存使用率<small>1-100%</small></span><input v-model.number="thresholdForm.memory_percent" type="number" min="1" max="100" required /></label><label><span>磁盘使用率<small>1-100%</small></span><input v-model.number="thresholdForm.disk_percent" type="number" min="1" max="100" required /></label><label><span>日志目录大小<small>MB</small></span><input v-model.number="thresholdForm.log_size_mb" type="number" min="1" max="1048576" required /></label><label><span>业务请求速率<small>请求/分钟</small></span><input v-model.number="thresholdForm.request_rate" type="number" min="1" max="1000000" required /></label></div><div class="modal-actions"><button type="button" class="secondary-button" @click="showThresholds = false">取消</button><button class="primary-button" type="submit" :disabled="saving">{{ saving ? '保存中…' : '应用阈值' }}</button></div></form></div>
  </section>
</template>
