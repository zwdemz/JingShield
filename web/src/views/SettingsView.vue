<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { DatabaseZap, RefreshCw, Save, ShieldCheck, SlidersHorizontal } from '@lucide/vue'
import { apiRequest, jsonBody } from '../api/client'
import WAFStatusView from './WAFStatusView.vue'
import type { ConfigItem, ProtectionSettings } from '../types/api'

const loading = ref(false)
const saving = ref('')
const error = ref('')
const notice = ref('')
const settings = ref<ProtectionSettings | null>(null)
const configs = ref<ConfigItem[]>([])
const behaviorDraft = ref<Record<string, string | number>>({})
const engineDescriptions: Record<string, string> = {
  cc_protection_status: '请求频率与验证策略，抵御高频访问',
  xss_protection_status: '脚本载荷与上下文敏感检测',
  sql_protection_status: 'SQL 语义、编码载荷与注入特征',
  path_traversal_protection_status: '目录穿越与路径规范化检测',
  ssrf_protection_status: '内网目标、DNS 解析与元数据端点检查',
  xxe_protection_status: '外部实体与高风险 XML 语义检测',
  scanner_protection_status: '同一站点 / IP 的敏感路径探测与扫描行为',
  policy_protection_status: '启用策略中心配置的自定义检测规则',
}
const behaviorKeys = ['behavior_window_seconds', 'behavior_threshold', 'behavior_block_seconds', 'behavior_mode']
const behaviorFields = [
  { key: 'behavior_window_seconds', label: '行为窗口（秒）', min: 10, max: 3600 },
  { key: 'behavior_threshold', label: '触发阈值', min: 2, max: 1000 },
  { key: 'behavior_block_seconds', label: '封禁时间（秒）', min: 10, max: 86400 },
]
const behaviorValid = computed(() => behaviorFields.every(field => {
  const value = Number(behaviorDraft.value[field.key]); return Number.isInteger(value) && value >= field.min && value <= field.max
}) && ['observe', 'block'].includes(String(behaviorDraft.value.behavior_mode)))
/** Return the API's string-valued settings after Vue converts number inputs to numbers. */
function behaviorPayloadValues(): Record<string, string> {
  return Object.fromEntries(behaviorKeys.map(key => [key, String(behaviorDraft.value[key] ?? '')]))
}
const globallyEnabled = computed(() => settings.value?.values.system_status === '1')
const fields = computed(() => configs.value.filter(item => ['cc_visit_count', 'cc_visit_time', 'cc_blacklist_time', 'cc_verify_fail_limit', 'cc_whitelist_time', 'cc_verification_mode', 'log_keep_days'].includes(item.config_key)))
const securityContact = computed(() => configs.value.find(item => item.config_key === 'security_contact'))
const profileLabels: Record<string, string> = { low: '宽松', standard: '标准', strict: '严格', custom: '自定义' }

function updateSettings(value: ProtectionSettings, resetBehavior = true) {
  settings.value = value
  if (resetBehavior) behaviorDraft.value = Object.fromEntries(behaviorKeys.map(key => [key, value.values[key] || '']))
}
async function load() {
  loading.value = true; error.value = ''
  try {
    const [protection, config] = await Promise.all([apiRequest<ProtectionSettings>('/protection/settings'), apiRequest<ConfigItem[]>('/config')])
    updateSettings(protection); configs.value = config
  } catch (cause) { error.value = cause instanceof Error ? cause.message : '配置加载失败' }
  finally { loading.value = false }
}
/** Persist one settings update and refresh affected CC fields only, preserving unrelated unsaved drafts. */
async function saveProtection(key: string, body: { profile?: string; values?: Record<string, string> }, message: string) {
  if (saving.value) return
  saving.value = key; error.value = ''; notice.value = ''
  try {
    await apiRequest('/protection/settings', { method: 'PUT', ...jsonBody(body) })
    const snapshot = await apiRequest<ProtectionSettings>('/protection/settings')
    const profileValues = snapshot.profiles.find(profile => profile.id === body.profile)?.values || {}
    const changedKeys = new Set([...Object.keys(profileValues), ...Object.keys(body.values || {})])
    for (const item of configs.value) {
      if (changedKeys.has(item.config_key) && Object.hasOwn(snapshot.values, item.config_key)) item.config_value = snapshot.values[item.config_key]
    }
    updateSettings(snapshot, ['behavior', 'low', 'standard', 'strict'].includes(key))
    notice.value = message
  } catch (cause) { error.value = cause instanceof Error ? cause.message : '防护设置保存失败，请刷新确认状态' }
  finally { saving.value = '' }
}
function toggle(key: string) {
  if (!settings.value) return
  const next = settings.value.values[key] === '1' ? '0' : '1'
  if (key === 'system_status' && next === '0' && !window.confirm('关闭 WAF 总开关将暂停全部引擎判定，确认继续？')) return
  void saveProtection(key, { values: { [key]: next } }, '防护开关已更新；独立调整后等级按实际配置重新判定。')
}
function applyProfile(profile: ProtectionSettings['profiles'][number]) {
  const names = Object.keys(profile.values).map(key => settings.value?.engines.find(engine => engine.key === key)?.label || key)
  if (!window.confirm(`应用“${profile.label}”会覆盖以下设置：\n${names.join('、')}\n不修改 WAF 总开关。确认应用？`)) return
  void saveProtection(profile.id, { profile: profile.id }, `已统一应用${profile.label}防护等级；可继续单独启停模块。`)
}
async function saveField(item: ConfigItem) {
  if (saving.value) return
  saving.value = item.config_key; error.value = ''
  try {
    await apiRequest('/config', { method: 'PUT', ...jsonBody({ config_key: item.config_key, config_value: item.config_value }) })
    // CC frequency fields participate in profile matching; refresh the confirmed
    // profile without replacing behavior or other independently edited drafts.
    if (['cc_visit_count', 'cc_visit_time'].includes(item.config_key)) updateSettings(await apiRequest<ProtectionSettings>('/protection/settings'), false)
    notice.value = `${item.config_desc || item.config_key}已更新`
  }
  catch (cause) { error.value = cause instanceof Error ? cause.message : '配置保存失败' }
  finally { saving.value = '' }
}
async function clearCache() {
  if (!window.confirm('确认清理运行时防护计数？这会影响当前防护窗口，不删除日志。')) return
  saving.value = 'cache'; error.value = ''
  try { await apiRequest('/cache', { method: 'DELETE' }); notice.value = '运行时防护计数已清理' }
  catch (cause) { error.value = cause instanceof Error ? cause.message : '缓存清理失败' }
  finally { saving.value = '' }
}
onMounted(load)
</script>

<template>
  <section class="page-content">
    <header class="page-header"><div><p class="eyebrow">PROTECTION POLICY</p><h1>防护配置</h1><p>按等级统一设置，也可独立启停引擎；实际运行状态在下方查看。</p></div><div class="header-actions"><button class="secondary-button" :disabled="loading || !!saving" @click="load"><RefreshCw :size="17" :class="{ spinning: loading }" />刷新</button></div></header>
    <p v-if="error" class="inline-alert" role="alert">{{ error }}</p><p v-if="notice" class="inline-success" role="status">{{ notice }}</p>
    <p v-if="loading && !settings" class="empty-state" role="status">正在读取防护设置…</p>
    <template v-if="settings">
      <article class="panel engine-master"><div><h2>WAF 总开关</h2><p>{{ globallyEnabled ? '引擎按下方各自配置运行' : '全部引擎实际暂停，以下显示已保存的配置状态' }}</p></div><button class="engine-switch" :class="{ active: globallyEnabled }" :disabled="!!saving || loading" role="switch" :aria-checked="globallyEnabled" aria-label="WAF 总开关" @click="toggle('system_status')"><span>{{ globallyEnabled ? '已开启' : '已暂停' }}</span><i></i></button></article>
      <article class="panel profile-panel"><div class="panel-heading"><div><span>防护等级</span><strong>当前：{{ profileLabels[settings.profile] || settings.profile }}</strong></div><ShieldCheck :size="21" /></div><div class="profile-grid"><button v-for="profile in settings.profiles" :key="profile.id" class="profile-card" :class="{ selected: settings.profile === profile.id }" :disabled="!!saving || loading" @click="applyProfile(profile)"><strong>{{ profile.label }}</strong><span>{{ profile.description }}</span><small>{{ saving === profile.id ? '正在应用…' : '查看覆盖范围并应用' }}</small></button></div><p class="section-note">等级应用为一次整体更新，不修改总开关。下面每个引擎可单独开关，点击后立即保存。</p></article>
      <div class="engine-grid"><article v-for="engine in settings.engines" :key="engine.key" class="panel engine-card" :class="{ enabled: engine.enabled }"><div><h2>{{ engine.label }}</h2><p>{{ engineDescriptions[engine.key] || '独立防护检测模块' }}</p><small>{{ engine.enabled ? (globallyEnabled ? '配置启用 · 运行中' : '配置启用 · 总开关已暂停') : '配置关闭' }}</small></div><button class="engine-switch" :class="{ active: engine.enabled }" :disabled="!!saving || loading" role="switch" :aria-checked="engine.enabled" :aria-label="engine.label" @click="toggle(engine.key)"><span>{{ saving === engine.key ? '保存中' : engine.enabled ? '开启' : '关闭' }}</span><i></i></button></article></div>
      <WAFStatusView :key="JSON.stringify(settings.values)" section="engines" />
      <div class="settings-grid">
        <form class="panel settings-panel behavior-panel" @submit.prevent="saveProtection('behavior', { values: behaviorPayloadValues() }, '行为检测参数已更新')"><div class="panel-heading"><div><span>行为检测与自动拦截</span><strong>先观察，再按业务调整阈值</strong></div><SlidersHorizontal :size="21" /></div><div class="settings-form"><label class="field-label" for="behavior-mode">处置模式</label><div class="input-shell"><select id="behavior-mode" v-model="behaviorDraft.behavior_mode"><option value="observe">观察：记录风险，不因行为评分封禁</option><option value="block">拦截：达到阈值后临时封禁</option></select></div><div class="form-grid"><div v-for="field in behaviorFields" :key="field.key"><label class="field-label" :for="field.key">{{ field.label }}</label><div class="input-shell"><input :id="field.key" v-model="behaviorDraft[field.key]" type="number" step="1" :min="field.min" :max="field.max" required /></div><small class="field-help">{{ field.min }}–{{ field.max }}</small></div></div><p class="field-help">结合请求行为累计风险。NAS 下载、音乐与 WebSocket 等正常流量应先观察；白名单优先。总开关关闭时不执行引擎判定。</p><div class="modal-actions"><button class="primary-button" :disabled="!!saving || !behaviorValid"><Save :size="16" />{{ saving === 'behavior' ? '保存中…' : '保存行为策略' }}</button></div></div></form>
        <article class="panel settings-panel"><div class="panel-heading"><div><span>CC 与日志阈值</span><strong>按项保存，立即生效</strong></div><SlidersHorizontal :size="21" /></div><div class="config-list"><label v-for="item in fields" :key="item.config_key"><span><strong>{{ item.config_desc || item.config_key }}</strong><small>{{ item.config_key }}</small></span><div><input v-model="item.config_value" inputmode="numeric" :aria-label="item.config_desc || item.config_key" /><button :disabled="!!saving" :aria-label="`保存 ${item.config_desc || item.config_key}`" @click="saveField(item)"><Save :size="16" /></button></div></label><label v-if="securityContact" class="text-config"><span><strong>拦截页联系信息</strong><small>security_contact</small></span><div><input v-model="securityContact.config_value" maxlength="200" /><button :disabled="!!saving" aria-label="保存拦截页联系信息" @click="saveField(securityContact)"><Save :size="16" /></button></div></label></div></article>
        <article class="panel maintenance-panel"><div class="maintenance-icon"><DatabaseZap :size="24" /></div><div><strong>清理运行时计数</strong><p>清理后当前防护窗口会重新累计，不删除数据库日志。</p></div><button class="secondary-button" :disabled="!!saving" @click="clearCache">{{ saving === 'cache' ? '清理中…' : '清理计数' }}</button></article>
      </div>
    </template>
  </section>
</template>
