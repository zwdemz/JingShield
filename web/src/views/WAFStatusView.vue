<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { Activity, Cable, RefreshCw, Save, ShieldCheck } from '@lucide/vue'
import { apiRequest, jsonBody } from '../api/client'
import BatchBlockDialog from '../components/BatchBlockDialog.vue'
import type { LinkageConfig, LinkageStatus, SyslogConfig, SyslogStatus, WAFRuntimeStatus, WhitelistPreview, WhitelistSyncResult } from '../types/api'

/** Show one operational concern inside its owning feature page. */
const props = defineProps<{ section: 'system' | 'audit' | 'behavior' | 'engines' | 'syslog' | 'linkage' }>()
const sectionLabels = { system: 'WAF 服务概况', audit: '审计追加状态', behavior: '行为检测状态', engines: '引擎运行状态', syslog: 'Syslog 配置与同步', linkage: '同协议设备联动' }
const runtime = ref<WAFRuntimeStatus | null>(null)
const syslog = ref<SyslogConfig | null>(null)
const syslogStatus = ref<SyslogStatus | null>(null)
const linkage = ref<LinkageConfig | null>(null)
const linkageStatus = ref<LinkageStatus | null>(null)
const linkageSaved = ref('')
const loading = ref(false)
const action = ref('')
const errors = ref<Record<string, string>>({})
const notice = ref('')
const autoRefresh = ref(true)
const retryFailed = ref(false)
const showBatch = ref(false)
const capabilities = ref<Record<string, unknown> | null>(null)
const whitelistPreview = ref<WhitelistPreview | null>(null)
const refreshedAt = ref('')
let timer: ReturnType<typeof setInterval> | undefined
let controller: AbortController | undefined
const linkageDirty = computed(() => JSON.stringify(linkage.value) !== linkageSaved.value)
const canRemoteBlock = computed(() => !!linkage.value?.enabled && !!linkageStatus.value?.compatible && !linkageDirty.value)
const canSyncWhitelist = computed(() => canRemoteBlock.value && !!linkage.value?.source_id)
const behavior = computed(() => {
  const value = runtime.value?.metrics.behavior
  return typeof value === 'object' ? value : {}
})
const metricLabels: Record<string, string> = {
  evaluated_total: '累计评估请求', blocked_total: '累计拦截', challenged_total: '累计挑战验证',
  evaluated: '已评估', scored: '已累计风险', observed: '观察命中', blocked: '行为封禁',
  observed_total: '累计观察命中', blocked_total_behavior: '累计行为封禁', scored_total: '累计风险计数',
  scanner_matches_total: '扫描器命中', behavior_blocks_total: '行为封禁次数', active_blocks: '活跃封禁',
  state_errors_total: '共享状态错误', state_error_total: '共享状态错误', state_failures_total: '共享状态失败',
  checked_total: '累计行为检查', probe_total: '敏感路径探测', matched_total: '行为规则命中', state_available: '状态服务已配置',
  window_seconds: '窗口（秒）', threshold: '触发阈值', block_seconds: '封禁（秒）', mode: '处置模式',
}
const vendors = ['360 网神', '华为', '中兴', '思科']
function numberMetric(key: string) { const value = runtime.value?.metrics[key]; return typeof value === 'number' ? value : 0 }
function formatTime(value?: string) { return value && !value.startsWith('0001-') ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '暂无记录' }
function uptime(value: number) { const hours = Math.floor(value / 3600); return `${Math.floor(hours / 24)} 天 ${hours % 24} 时 ${Math.floor(value % 3600 / 60)} 分` }
function message(cause: unknown) { return cause instanceof Error ? cause.message : '读取失败，请重试' }

/** Refresh independent status sources without replacing unsaved configuration drafts. */
async function load(withConfig: false | 'all' | 'syslog' | 'linkage' = false, afterAction = false) {
  if (loading.value || (action.value && !afterAction)) return
  loading.value = true
  controller?.abort(); controller = new AbortController()
  const signal = controller.signal
  const tasks: Promise<void>[] = []
  if (['system', 'audit', 'behavior', 'engines'].includes(props.section)) tasks.push(
    apiRequest<WAFRuntimeStatus>('/system/waf-status', { signal }).then(value => {
      if (signal.aborted) return
      runtime.value = value; delete errors.value.runtime
    }).catch(cause => { if (!signal.aborted) errors.value.runtime = message(cause) }),
  )
  if (props.section === 'syslog') tasks.push(
    apiRequest<{ config: SyslogConfig; status: SyslogStatus }>('/system/syslog', { signal }).then(value => {
      if (signal.aborted) return
      syslogStatus.value = value.status
      if (withConfig === 'all' || withConfig === 'syslog' || !syslog.value) syslog.value = { ...value.config }
      delete errors.value.syslog
    }).catch(cause => { if (!signal.aborted) errors.value.syslog = message(cause) }),
  )
  if (props.section === 'linkage') tasks.push(
    apiRequest<{ config: LinkageConfig; status: LinkageStatus }>('/system/linkage', { signal }).then(value => {
      if (signal.aborted) return
      linkageStatus.value = value.status
      if (withConfig === 'all' || withConfig === 'linkage' || !linkage.value) {
        linkage.value = { ...value.config, source_id: value.config.source_id || '' }
        linkageSaved.value = JSON.stringify(linkage.value)
      }
      delete errors.value.linkage
    }).catch(cause => { if (!signal.aborted) errors.value.linkage = message(cause) }),
  )
  await Promise.all(tasks)
  if (signal.aborted) return
  refreshedAt.value = new Date().toLocaleTimeString('zh-CN', { hour12: false })
  loading.value = false
}

/** Persist Syslog configuration; success means configuration saved, not remote receipt. */
async function saveSyslog() {
  if (!syslog.value || action.value) return
  action.value = 'syslog'; notice.value = ''; delete errors.value.syslog
  try {
    await apiRequest('/system/syslog', { method: 'PUT', ...jsonBody(syslog.value) })
    notice.value = 'Syslog 配置已保存。传输计数只表示发送结果，请在接收端核对日志。'
    await load('syslog', true)
  } catch (cause) { errors.value.syslog = message(cause) }
  finally { action.value = '' }
}
async function syncSyslog() {
  if (action.value) return
  action.value = 'sync'; notice.value = ''; delete errors.value.syslog
  try {
    await apiRequest('/system/syslog/sync', { method: 'POST', ...jsonBody({ retry_failed: retryFailed.value }) })
    notice.value = retryFailed.value ? '已请求重新处理失败队列，可能重复投递。请刷新查看传输结果，远端接收需另行确认。' : '已唤醒待发送队列；不是远端接收或封禁确认。'
    await load(false, true)
  } catch (cause) { errors.value.syslog = message(cause) }
  finally { action.value = '' }
}
async function saveLinkage() {
  if (!linkage.value || action.value) return
  action.value = 'linkage'; notice.value = ''; delete errors.value.linkage; capabilities.value = null; whitelistPreview.value = null
  try {
    await apiRequest('/system/linkage', { method: 'PUT', ...jsonBody(linkage.value) })
    notice.value = '联动配置已保存。请先验证协议能力，再下发 IP 封禁。'
    await load('linkage', true)
  } catch (cause) { errors.value.linkage = message(cause) }
  finally { action.value = '' }
}
async function probe() {
  if (action.value || linkageDirty.value) return
  action.value = 'probe'; notice.value = ''; delete errors.value.linkage
  try {
    capabilities.value = await apiRequest<Record<string, unknown>>('/system/linkage/probe', { method: 'POST' })
    notice.value = '协议探测完成，请依据兼容状态决定是否下发。探测成功不代表任何 IP 已封禁。'
    await load(false, true)
  } catch (cause) { await load(false, true); errors.value.linkage = message(cause) }
  finally { action.value = '' }
}
/** Preview the exact local-only snapshot before an explicit remote push. */
async function previewWhitelist() {
  if (action.value || !canSyncWhitelist.value) return
  action.value = 'whitelist-preview'; notice.value = ''; delete errors.value.linkage
  try { whitelistPreview.value = await apiRequest<WhitelistPreview>('/system/linkage/whitelist/preview') }
  catch (cause) { errors.value.linkage = message(cause) }
  finally { action.value = '' }
}
/** Send a preflight-checked complete snapshot; the backend rechecks digest and peer capability. */
async function pushWhitelist() {
  if (action.value || !canSyncWhitelist.value || !whitelistPreview.value) return
  if (!window.confirm(`确认将 ${whitelistPreview.value.count} 条白名单作为完整快照下发到 ${linkage.value?.endpoint}？空快照会清除该来源此前下发的规则。`)) return
  action.value = 'whitelist-push'; notice.value = ''; delete errors.value.linkage
  try {
    const result = await apiRequest<WhitelistSyncResult>('/system/linkage/whitelist/sync', { method: 'POST', ...jsonBody({ expected_digest: whitelistPreview.value.digest }) })
    notice.value = `对端已确认接收来源 ${result.source} 的 ${result.count} 条白名单规则。已有黑名单的优先级以接收端策略为准。`
    whitelistPreview.value = null
    await load(false, true)
  } catch (cause) { errors.value.linkage = message(cause); whitelistPreview.value = null }
  finally { action.value = '' }
}
onMounted(() => {
  void load(props.section === 'syslog' ? 'syslog' : props.section === 'linkage' ? 'linkage' : false)
  timer = setInterval(() => { if (autoRefresh.value && !document.hidden) void load() }, 15000)
})
onBeforeUnmount(() => { if (timer) clearInterval(timer); controller?.abort() })
</script>

<template>
  <section class="waf-section" :aria-label="sectionLabels[section]">
    <div class="status-toolbar"><label><input v-model="autoRefresh" type="checkbox" />每 15 秒刷新状态</label><span>{{ loading ? '读取中…' : refreshedAt ? `上次读取 ${refreshedAt}` : '尚未读取' }}</span><span v-if="runtime">服务端 {{ formatTime(runtime.server_time) }}</span><button type="button" class="secondary-button" :disabled="loading || !!action" @click="load()"><RefreshCw :size="16" :class="{ spinning: loading }" />刷新状态</button></div>
    <p v-if="notice" class="inline-success" role="status">{{ notice }}</p>
    <p v-if="errors.runtime" class="inline-alert" role="alert">运行状态读取失败：{{ errors.runtime }}；以下如有旧数据，不代表当前状态。</p>
    <div v-if="section === 'system' && runtime" class="status-metrics panel runtime-summary"><div><span>WAF 总状态</span><strong :class="runtime.waf_enabled ? 'tone-cyan' : 'tone-amber'">{{ runtime.waf_enabled ? '防护开启' : '防护暂停' }}</strong><small>{{ runtime.protection.engines.filter(item => item.enabled).length }} / {{ runtime.protection.engines.length }} 个引擎配置启用</small></div><div><span>状态后端</span><strong>{{ runtime.state_backend }}</strong><small>{{ runtime.shared_state ? '多节点共享状态' : '仅当前节点，重启不保留内存状态' }}</small></div><div><span>运行时长</span><strong>{{ uptime(runtime.uptime_seconds) }}</strong><small>启动 {{ formatTime(runtime.started_at) }}</small></div><div><span>防护站点</span><strong>{{ runtime.sites.enabled }} / {{ runtime.sites.total }}</strong><small>启用 / 全部</small></div></div>
    <article v-if="section === 'audit' && runtime" class="panel operations-panel"><div class="panel-heading"><div><span>请求与审计追加状态</span><strong>当前进程累计，重启后重新计数</strong></div><Activity :size="20" /></div><div class="status-metrics"><div v-for="key in ['evaluated_total', 'blocked_total', 'challenged_total']" :key="key"><span>{{ metricLabels[key] }}</span><strong>{{ numberMetric(key).toLocaleString() }}</strong></div></div><dl class="status-details"><div><dt>访问日志队列</dt><dd>{{ numberMetric('access_queue_depth') }} / {{ numberMetric('access_queue_capacity') }}</dd></div><div><dt>攻击日志队列</dt><dd>{{ numberMetric('attack_queue_depth') }} / {{ numberMetric('attack_queue_capacity') }}</dd></div><div><dt>审计追加失败</dt><dd :class="{ 'tone-red': numberMetric('audit_failed_total') > 0 }">{{ numberMetric('audit_failed_total') }}</dd></div><div><dt>审计丢弃（队列压力）</dt><dd :class="{ 'tone-red': numberMetric('audit_dropped_total') > 0 }">{{ numberMetric('audit_dropped_total') }}</dd></div><div><dt>平均判定耗时</dt><dd>{{ (numberMetric('evaluation_nanoseconds_total') / Math.max(1, numberMetric('evaluated_total')) / 1e6).toFixed(3) }} ms</dd></div></dl></article>
    <article v-if="section === 'behavior' && runtime" class="panel operations-panel"><div class="panel-heading"><div><span>行为检测运行指标</span><strong>{{ runtime.waf_enabled ? '实时运行指标' : '总开关关闭：引擎实际暂停' }}</strong></div><ShieldCheck :size="20" /></div><dl class="status-details"><div v-for="(value, key) in behavior" :key="key"><dt>{{ metricLabels[key] || key }}</dt><dd>{{ typeof value === 'boolean' ? value ? '已配置' : '未配置' : value === 'observe' ? '观察' : value === 'block' ? '自动拦截' : value }}</dd></div></dl><div v-if="!Object.keys(behavior).length" class="section-note">当前节点未提供行为统计。</div></article>
    <article v-if="section === 'engines' && runtime" class="panel operations-panel"><div class="panel-heading"><div><span>引擎实际运行状态</span><strong>{{ runtime.waf_enabled ? '与当前配置联动' : '总开关关闭：全部暂停' }}</strong></div><ShieldCheck :size="20" /></div><ul class="runtime-engine-list"><li v-for="engine in runtime.protection.engines" :key="engine.key"><span>{{ engine.label }}</span><b :class="{ 'tone-cyan': engine.enabled && runtime.waf_enabled }">{{ engine.enabled ? runtime.waf_enabled ? '运行中' : '配置启用 / 暂停' : '关闭' }}</b></li></ul></article>

    <article v-if="section === 'syslog'" id="syslog" class="panel operations-panel"><div class="panel-heading"><div><span>Syslog 配置与同步</span><strong>RFC 5424 · 独立审计输出，不等同 WAF 封禁联动</strong></div><RefreshCw :size="20" /></div><p v-if="errors.syslog" class="inline-alert" role="alert">{{ errors.syslog }}</p><div class="operations-grid embedded-grid">
      <form v-if="syslog" class="settings-form" @submit.prevent="saveSyslog"><label class="checkbox-field"><input :disabled="!!action || loading" v-model="syslog.enabled" type="checkbox" />启用 Syslog 输出</label><div class="form-grid"><div><label for="syslog-transport" class="field-label">传输协议</label><div class="input-shell"><select :disabled="!!action || loading" id="syslog-transport" v-model="syslog.transport"><option value="tls">TLS（推荐）</option><option value="tcp">TCP（明文）</option><option value="udp">UDP（无接收确认）</option></select></div></div><div><label for="syslog-address" class="field-label">接收地址 host:port</label><div class="input-shell"><input :disabled="!!action || loading" id="syslog-address" v-model="syslog.address" :required="syslog.enabled" placeholder="logs.example.com:6514" maxlength="255" /></div></div><div v-if="syslog.transport === 'tls'"><label for="syslog-server" class="field-label">TLS 服务器名称</label><div class="input-shell"><input :disabled="!!action || loading" id="syslog-server" v-model="syslog.server_name" placeholder="匹配证书域名，默认接收主机" maxlength="255" /></div></div><div><label for="syslog-facility" class="field-label">Facility（0–23）</label><div class="input-shell"><input :disabled="!!action || loading" id="syslog-facility" v-model.number="syslog.facility" type="number" min="0" max="23" required /></div></div><div><label for="syslog-timeout" class="field-label">连接超时（秒）</label><div class="input-shell"><input :disabled="!!action || loading" id="syslog-timeout" v-model.number="syslog.timeout_seconds" type="number" min="1" max="10" required /></div></div><div><label for="syslog-retries" class="field-label">最大重试次数</label><div class="input-shell"><input :disabled="!!action || loading" id="syslog-retries" v-model.number="syslog.max_retries" type="number" min="0" max="5" required /></div></div><div><label for="syslog-capacity" class="field-label">有界队列容量</label><div class="input-shell"><input :disabled="!!action || loading" id="syslog-capacity" v-model.number="syslog.queue_capacity" type="number" min="1" max="10000" required /></div></div></div><p class="field-help">TLS 校验证书；TCP/UDP 会以明文发送。重试可能产生重复记录，接收端应按事件 ID 去重。</p><div class="modal-actions"><button class="primary-button" :disabled="!!action || loading"><Save :size="16" />{{ action === 'syslog' ? '保存中…' : '保存 Syslog 配置' }}</button></div></form>
      <section v-if="syslogStatus" class="sync-status"><h2>同步 / 追加传输状态</h2><dl class="status-details"><div><dt>发送工作器</dt><dd>{{ syslogStatus.running ? '运行' : '停止' }}</dd></div><div><dt>等待发送 / 容量</dt><dd>{{ syslogStatus.queued }} / {{ syslogStatus.queue_capacity }}</dd></div><div><dt>失败待重试</dt><dd>{{ syslogStatus.failed }}</dd></div><div><dt>已传输 / 重试 / 丢弃</dt><dd>{{ syslogStatus.sent_total }} / {{ syslogStatus.retried_total }} / {{ syslogStatus.dropped_total }}</dd></div><div><dt>最后传输成功</dt><dd>{{ formatTime(syslogStatus.last_success) }}</dd></div><div><dt>最后错误</dt><dd :class="{ 'tone-red': !!syslogStatus.last_error }">{{ syslogStatus.last_error || '无' }}</dd></div></dl><p class="threshold-note">传输成功仅指本地写入连接或数据报成功，不保证远端接收、持久化，更不表示防火墙 / WAF 已封禁 IP。待发送 / 失败项持久化并在重启后恢复；传输、重试、丢弃计数及最后状态仅统计当前进程。</p><label class="checkbox-field"><input v-model="retryFailed" type="checkbox" />同时重试失败项（可能重复投递）</label><button class="secondary-button full-button" :disabled="!!action || loading || !syslog?.enabled" @click="syncSyslog">{{ action === 'sync' ? '正在唤醒…' : '立即同步待发送日志' }}</button></section>
    </div></article>

    <article v-if="section === 'linkage'" id="linkage" class="panel operations-panel"><div class="panel-heading"><div><span>同协议 WAF / 防火墙联动</span><strong>JINGSHIELD-V1 · HTTPS · 能力握手后下发</strong></div><Cable :size="20" /></div><p v-if="errors.linkage" class="inline-alert" role="alert">{{ errors.linkage }}</p><div class="operations-grid embedded-grid"><form v-if="linkage" class="settings-form" @submit.prevent="saveLinkage"><label class="checkbox-field"><input :disabled="!!action || loading" v-model="linkage.enabled" type="checkbox" />启用同协议封禁联动</label><div class="form-grid"><div><label for="linkage-vendor" class="field-label">设备品牌标签（不代表原生兼容）</label><div class="input-shell"><select :disabled="!!action || loading" id="linkage-vendor" v-model="linkage.device_vendor"><option value="">未指定</option><option value="jingshield">捷云鲸盾</option><option value="system">Linux nftables / ipset 桥接</option><option value="360">360 网神</option><option value="huawei">华为</option><option value="zte">中兴</option><option value="cisco">思科</option><option value="adapter">其他同协议适配器</option></select></div></div><div><label for="linkage-type" class="field-label">设备角色</label><div class="input-shell"><select :disabled="!!action || loading" id="linkage-type" v-model="linkage.device_type"><option value="waf">WAF（本产品 / 同协议）</option><option value="firewall">防火墙（需同协议适配器）</option></select></div></div><div><label for="linkage-protocol" class="field-label">应用协议</label><div class="input-shell"><input :disabled="!!action || loading" id="linkage-protocol" :value="linkage.protocol" readonly /></div></div><div class="full-field"><label for="linkage-url" class="field-label">对端 HTTPS 地址</label><div class="input-shell"><input :disabled="!!action || loading" id="linkage-url" v-model="linkage.endpoint" type="url" :required="linkage.enabled" placeholder="https://waf-peer.example.com:8443" /></div></div><div><label for="linkage-secret" class="field-label">API 密钥环境变量名（不是密钥值）</label><div class="input-shell"><input :disabled="!!action || loading" id="linkage-secret" v-model="linkage.secret_env" :required="linkage.enabled" pattern="JINGSHIELD_LINKAGE_[A-Z0-9_]{1,100}" maxlength="119" autocomplete="off" /></div></div><div><label for="linkage-timeout" class="field-label">请求超时（秒）</label><div class="input-shell"><input :disabled="!!action || loading" id="linkage-timeout" v-model.number="linkage.timeout_seconds" type="number" min="1" max="10" required /></div></div></div><p class="field-help">环境变量名须以 JINGSHIELD_LINKAGE_ 开头。密钥通过容器 / 系统环境变量配置，不在页面回显。必须有受信任 TLS 证书，禁止使用跳过验证。保存后先探测协议能力。</p><div class="modal-actions"><button class="primary-button" :disabled="!!action || loading"><Save :size="16" />{{ action === 'linkage' ? '保存中…' : '保存联动配置' }}</button></div></form><section v-if="linkageStatus" class="sync-status"><h2>联动结果</h2><dl class="status-details"><div><dt>协议兼容性</dt><dd :class="canRemoteBlock ? 'tone-cyan' : 'tone-amber'">{{ linkageDirty ? '配置待保存' : linkageStatus.compatible ? '握手兼容' : '未验证 / 不兼容' }}</dd></div><div><dt>最近探测</dt><dd>{{ formatTime(linkageStatus.last_probe) }}</dd></div><div><dt>最近成功</dt><dd>{{ formatTime(linkageStatus.last_success) }}</dd></div><div><dt>最近错误</dt><dd>{{ linkageStatus.last_error || '无' }}</dd></div><div v-if="linkageStatus.last_result"><dt>最近批量响应</dt><dd>封禁 {{ linkageStatus.last_result.blocked }} / 白名单跳过 {{ linkageStatus.last_result.skipped_whitelist }}</dd></div></dl><div class="action-stack"><button class="secondary-button" :disabled="!!action || loading || linkageDirty || !linkage?.enabled" @click="probe">{{ action === 'probe' ? '探测中…' : '探测同协议能力' }}</button><button class="primary-button" :disabled="!!action || loading || !canRemoteBlock" @click="showBatch = true">联动封禁 IP（上限 500）</button></div><p class="field-help">封禁在显式确认后下发，以对端 API 返回为依据；不因 Syslog 成功而标记封禁成功。</p><details v-if="capabilities" class="capability-details"><summary>查看对端能力声明</summary><pre>{{ JSON.stringify(capabilities, null, 2) }}</pre></details></section></div>
      <section v-if="linkage" class="compatibility-matrix" aria-label="白名单同步"><h2>白名单接收与下发</h2><p class="field-help">仅发送本机手工白名单；接收端按来源替换规则，不会删除其他来源或本机手工规则。来源 ID 须在各发送节点唯一。</p><label for="linkage-source" class="field-label">本节点来源 ID</label><div class="input-shell"><input id="linkage-source" v-model="linkage.source_id" maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9_-]{0,63}" placeholder="例如 nas_waf_01" :disabled="!!action || loading" /></div><p class="field-help">修改后使用上方“保存联动配置”保存，再探测能力；空快照会清除本来源上次下发的全部规则。</p><div class="action-stack"><button class="secondary-button" :disabled="!!action || loading || !canSyncWhitelist" @click="previewWhitelist">预览本机白名单</button><button class="primary-button" :disabled="!!action || loading || !canSyncWhitelist || !whitelistPreview" @click="pushWhitelist">确认并下发快照</button></div><details v-if="whitelistPreview" open class="capability-details"><summary>待下发：{{ whitelistPreview.count }} 条，来源 {{ whitelistPreview.source }}</summary><pre>{{ whitelistPreview.rules.join('\n') || '空快照：清除该来源的旧规则' }}</pre></details><p v-if="linkageStatus?.last_whitelist" class="field-help">最近确认：{{ linkageStatus.last_whitelist.source }} · {{ linkageStatus.last_whitelist.count }} 条 · 版本 {{ linkageStatus.last_whitelist.revision }}</p></section>
      <div class="compatibility-matrix"><h2>产品与协议兼容边界</h2><p class="field-help">品牌相同不等于接口兼容。事件接入协议（CEF / LEEF / Syslog）也不等于远程封禁协议。</p><div class="table-scroll"><table><thead><tr><th>产品 / 设备</th><th>当前支持方式</th><th>交付状态</th></tr></thead><tbody><tr><td>捷云鲸盾 WAF</td><td>jingshield-v1 握手、封禁、白名单接收与下发</td><td>已实现，实际对端须验证</td></tr><tr><td>Linux nftables / ipset</td><td>同协议桥接；apply 模式持久接收白名单并清理托管封禁</td><td>需实际握手和实机验证</td></tr><tr v-for="vendor in vendors" :key="vendor"><td>{{ vendor }}</td><td>需型号、固件 / OS 版本与对应封禁 API 或适配器</td><td>原生接口未适配 / 未验证</td></tr></tbody></table></div></div>
    </article>
    <BatchBlockDialog v-if="section === 'linkage' && showBatch" remote endpoint="/system/linkage/block-batch" @close="showBatch = false" @completed="result => { notice = `对端确认封禁 ${result.blocked} 个，白名单跳过 ${result.skipped_whitelist} 个`; load() }" />
  </section>
</template>
