<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Cable, Check, Clipboard, KeyRound, RefreshCw, RotateCw, Save, ServerCog, Terminal } from '@lucide/vue'
import { apiRequest, jsonBody } from '../api/client'
import type { DeviceEvent, DeviceSettings, IntegrationConfig, PageData } from '../types/api'

const config = ref<IntegrationConfig | null>(null)
const deviceSettings = ref<DeviceSettings | null>(null)
const events = ref<DeviceEvent[]>([])
const newKey = ref('')
const loading = ref(false)
const error = ref('')
const notice = ref('')
const copied = ref(false)
const formats = [
  { name: 'CEF', vendors: 'Fortinet / Palo Alto / Check Point / 华为 / 深信服', path: 'cef' },
  { name: 'LEEF', vendors: 'IBM QRadar 生态与兼容设备', path: 'leef' },
  { name: 'Suricata EVE', vendors: 'Suricata IDS/IPS JSON 事件', path: 'suricata' },
  { name: 'Wazuh', vendors: 'Wazuh Manager 告警 Webhook', path: 'wazuh' },
  { name: 'Generic JSON', vendors: 'EDR / SIEM / SOAR 自定义集成', path: 'json' },
]
const baseURL = computed(() => window.location.origin)
const curlExample = computed(() => `curl -k '${baseURL.value}/openapi/v1/events/json' \\
  -H 'X-API-Key: <API_KEY>' \\
  -H 'Content-Type: application/json' \\
  -d '{"device_name":"edr-01","vendor":"Generic","event_type":"malware","severity":9,"event_ip":"203.0.113.10","message":"malware detected"}'`)

async function load() {
  loading.value = true
  try {
    const [integration, settings, eventPage] = await Promise.all([
      apiRequest<IntegrationConfig>('/integration'), apiRequest<DeviceSettings>('/integration/device-settings'),
      apiRequest<PageData<DeviceEvent>>('/device-events?page=1&size=6'),
    ])
    config.value = integration; deviceSettings.value = settings; events.value = eventPage.list; error.value = ''
  } catch (reason) { error.value = reason instanceof Error ? reason.message : '联动配置加载失败' }
  finally { loading.value = false }
}
async function toggle() {
  if (!config.value) return
  const enabled = !config.value.enabled
  try { await apiRequest<null>('/integration/status', { method: 'PUT', ...jsonBody({ enabled }) }); config.value.enabled = enabled; notice.value = `API 联动已${enabled ? '启用' : '停用'}` }
  catch (reason) { error.value = reason instanceof Error ? reason.message : '状态更新失败' }
}
async function rotate() {
  if (!window.confirm('轮换后旧 API Key 会立即失效，确认继续？')) return
  try { const result = await apiRequest<{ api_key: string }>('/integration/api-key/rotate', { method: 'POST' }); newKey.value = result.api_key; notice.value = '新 API Key 已生成，请立即复制并更新联动设备'; await load() }
  catch (reason) { error.value = reason instanceof Error ? reason.message : '密钥轮换失败' }
}
async function saveDeviceSettings() {
  if (!deviceSettings.value) return
  try { await apiRequest('/integration/device-settings', { method: 'PUT', ...jsonBody(deviceSettings.value) }); notice.value = '设备联动响应策略已保存' }
  catch (reason) { error.value = reason instanceof Error ? reason.message : '设备联动配置保存失败' }
}
async function copy(value: string) {
  await navigator.clipboard.writeText(value); copied.value = true
  window.setTimeout(() => { copied.value = false }, 1800)
}
onMounted(load)
</script>

<template>
  <section class="page-content">
    <header class="page-header"><div><p class="eyebrow">SECURITY AUTOMATION</p><h1>安全设备联动</h1><p>接收主流安全设备事件，归一化风险字段并按严重度自动响应。</p></div><button class="secondary-button" :disabled="loading" @click="load"><RefreshCw :size="17" :class="{ spinning: loading }" /> 刷新</button></header>
    <p v-if="error" class="inline-alert">{{ error }}</p><p v-if="notice" class="inline-success">{{ notice }}</p>
    <div v-if="config" class="integration-grid">
      <article class="panel integration-main"><div class="panel-heading"><div><span>联动通道</span><strong>X-API-KEY AUTHENTICATION</strong></div><Cable :size="20" /></div><div class="integration-status"><div class="integration-icon"><Cable :size="26" /></div><div><strong>{{ config.enabled ? 'API 接入已开放' : 'API 接入已停用' }}</strong><p>管理后台会话不等于联动权限，外部请求必须携带独立密钥。</p></div><button class="switch-control" :class="{ active: config.enabled }" role="switch" :aria-checked="config.enabled" @click="toggle"><i></i></button></div><div class="key-panel"><div><span>当前密钥</span><code>{{ config.key_configured ? config.key_masked : '尚未生成' }}</code></div><button class="secondary-button" @click="rotate"><RotateCw :size="15" /> 轮换密钥</button></div><div v-if="newKey" class="new-key"><div><KeyRound :size="18" /><span><strong>仅显示这一次</strong><code>{{ newKey }}</code></span></div><button class="secondary-button compact-button" @click="copy(newKey)"><Check v-if="copied" :size="14" /><Clipboard v-else :size="14" /> {{ copied ? '已复制' : '复制' }}</button></div></article>
      <article class="panel integration-guide"><div class="panel-heading"><div><span>快速接入</span><strong>HTTPS EVENT EXAMPLE</strong></div><Terminal :size="20" /></div><div class="code-sample"><pre>{{ curlExample }}</pre><button title="复制示例" @click="copy(curlExample)"><Clipboard :size="15" /></button></div><p>自签名测试证书使用 <code>-k</code>；生产环境请导入 CA 或替换为受信任证书。</p></article>
      <article class="panel endpoint-panel"><div class="panel-heading"><div><span>开放接口</span><strong>OPENAPI V1</strong></div></div><ul><li v-for="endpoint in config.endpoints" :key="endpoint.path"><b :class="endpoint.method.toLowerCase()">{{ endpoint.method }}</b><code>{{ endpoint.path }}</code><span>{{ endpoint.description }}</span></li></ul><footer>临时封禁时传 <code>expire_seconds</code>（1-31536000）；传 0 表示永久封禁。</footer></article>
      <article class="panel device-format-panel"><div class="panel-heading"><div><span>设备兼容矩阵</span><strong>EVENT NORMALIZATION</strong></div><ServerCog :size="20" /></div><div class="device-format-grid"><div v-for="format in formats" :key="format.path" class="device-format-card"><strong>{{ format.name }}</strong><span>{{ format.vendors }}</span><code>/events/{{ format.path }}</code></div></div><form v-if="deviceSettings" class="device-settings" @submit.prevent="saveDeviceSettings"><div class="switch-row"><span><strong>高危事件自动临时封禁</strong><span>命中阈值且事件 IP 合法时写入临时黑名单</span></span><button type="button" class="switch-control" :class="{ active: deviceSettings.auto_block_enabled }" @click="deviceSettings.auto_block_enabled = !deviceSettings.auto_block_enabled"><i></i></button></div><div class="device-setting-fields"><div><label class="field-label">触发严重度（1-10）</label><div class="input-shell"><input v-model.number="deviceSettings.auto_block_severity" type="number" min="1" max="10" /></div></div><div><label class="field-label">封禁时长（秒）</label><div class="input-shell"><input v-model.number="deviceSettings.auto_block_seconds" type="number" min="60" max="31536000" /></div></div></div><div class="modal-actions"><button class="primary-button"><Save :size="15" /> 保存响应策略</button></div></form></article>
      <article class="panel device-event-panel"><div class="panel-heading"><div><span>最近设备事件</span><strong>NORMALIZED SECURITY FEED</strong></div></div><ul class="device-event-list"><li v-for="event in events" :key="event.id"><b class="severity-pill" :class="{ high: event.severity >= 8 }">S{{ event.severity }}</b><strong>{{ event.vendor }} / {{ event.format.toUpperCase() }}</strong><span>{{ event.event_type }} · {{ event.message || '无详细信息' }}</span><span>{{ event.action_taken === 'temporary_block' ? '已临时封禁' : '已记录' }} {{ event.event_ip }}</span></li></ul><div v-if="!events.length" class="empty-state">尚未收到外部安全设备事件</div></article>
    </div>
  </section>
</template>
