<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { CloudDownload, Download, Pencil, Plus, RefreshCw, Sparkles, Trash2, Upload, X } from '@lucide/vue'
import { apiRequest, jsonBody } from '../api/client'
import type { PolicyRecommendation, PolicyRule, PolicySettings } from '../types/api'

type RuleDraft = Omit<PolicyRule, 'id' | 'source' | 'version' | 'created_at' | 'updated_at'>
const blankRule = (): RuleDraft => ({ name: '', category: '自定义', target: 'all', pattern: '', action: 1, enabled: true, priority: 500, description: '' })
const rules = ref<PolicyRule[]>([])
const settings = ref<PolicySettings | null>(null)
const recommendations = ref<PolicyRecommendation[]>([])
const loading = ref(false)
const error = ref('')
const notice = ref('')
const showRule = ref(false)
const showImport = ref(false)
const showUpdate = ref(false)
const editingID = ref(0)
const draft = reactive<RuleDraft>(blankRule())
const importJSON = ref(JSON.stringify({ schema: 'jingshield.rules/v1', version: '2026.08.05', rules: [blankRule()] }, null, 2))
const updateDraft = reactive({ auto_update: false, url: '', interval_minutes: 360, public_key: '' })
const counts = computed(() => ({ custom: settings.value?.counts.custom || 0, imported: settings.value?.counts.import || 0, auto: settings.value?.counts.auto || 0 }))

function message(reason: unknown, fallback: string) { return reason instanceof Error ? reason.message : fallback }
function flash(text: string) { notice.value = text; window.setTimeout(() => { if (notice.value === text) notice.value = '' }, 3200) }
async function load() {
  loading.value = true
  try {
    const [ruleList, policySettings, recData] = await Promise.all([
      apiRequest<PolicyRule[]>('/policies'), apiRequest<PolicySettings>('/policies/settings'),
      apiRequest<{ recommendations: PolicyRecommendation[] }>('/policies/recommendations'),
    ])
    rules.value = ruleList; settings.value = policySettings; recommendations.value = recData.recommendations
    Object.assign(updateDraft, { auto_update: policySettings.auto_update, url: policySettings.url, interval_minutes: policySettings.interval_minutes, public_key: '' })
    error.value = ''
  } catch (reason) { error.value = message(reason, '策略数据加载失败') }
  finally { loading.value = false }
}
function openCreate() { editingID.value = 0; Object.assign(draft, blankRule()); showRule.value = true }
function openEdit(rule: PolicyRule) {
  editingID.value = rule.id
  Object.assign(draft, { name: rule.name, category: rule.category, target: rule.target, pattern: rule.pattern, action: rule.action, enabled: rule.enabled, priority: rule.priority, description: rule.description })
  showRule.value = true
}
async function saveRule() {
  try {
    const path = editingID.value ? `/policies/${editingID.value}` : '/policies'
    await apiRequest(path, { method: editingID.value ? 'PUT' : 'POST', ...jsonBody(draft) })
    showRule.value = false; flash(editingID.value ? '策略已更新并热加载' : '策略已创建并热加载'); await load()
  } catch (reason) { error.value = message(reason, '策略保存失败') }
}
async function toggleRule(rule: PolicyRule) {
  try { await apiRequest(`/policies/${rule.id}`, { method: 'PUT', ...jsonBody({ ...rule, enabled: !rule.enabled }) }); await load() }
  catch (reason) { error.value = message(reason, '策略状态更新失败') }
}
async function removeRule(rule: PolicyRule) {
  if (!window.confirm(`确认删除策略“${rule.name}”？`)) return
  try { await apiRequest(`/policies/${rule.id}`, { method: 'DELETE' }); flash('策略已删除'); await load() }
  catch (reason) { error.value = message(reason, '策略删除失败') }
}
async function importRules() {
  try { const pack = JSON.parse(importJSON.value); const result = await apiRequest<{ count: number }>('/policies/import', { method: 'POST', ...jsonBody(pack) }); showImport.value = false; flash(`已原子导入 ${result.count} 条策略`); await load() }
  catch (reason) { error.value = message(reason, '规则包不是合法 JSON 或导入失败') }
}
function downloadTemplate() {
  const blob = new Blob([importJSON.value], { type: 'application/json' }); const url = URL.createObjectURL(blob)
  const link = document.createElement('a'); link.href = url; link.download = 'jingshield-rules.json'; link.click(); URL.revokeObjectURL(url)
}
async function saveUpdateSettings() {
  try { await apiRequest('/policies/settings', { method: 'PUT', ...jsonBody(updateDraft) }); showUpdate.value = false; flash('自动更新配置已保存'); await load() }
  catch (reason) { error.value = message(reason, '自动更新配置保存失败') }
}
async function updateNow() {
  try { const result = await apiRequest<{ version: string; count: number }>('/policies/update-now', { method: 'POST' }); flash(`已更新到 ${result.version}，载入 ${result.count} 条规则`); await load() }
  catch (reason) { error.value = message(reason, '在线更新失败，原有策略未变更') }
}
async function applyRecommendation(item: PolicyRecommendation) {
  if (!item.config_key || item.recommended === undefined) return
  try { await apiRequest('/policies/recommendations/apply', { method: 'POST', ...jsonBody({ config_key: item.config_key, value: item.recommended }) }); flash('优化建议已应用'); await load() }
  catch (reason) { error.value = message(reason, '优化建议应用失败') }
}
onMounted(load)
</script>

<template>
  <section class="page-content">
    <header class="page-header"><div><p class="eyebrow">POLICY INTELLIGENCE</p><h1>策略中心</h1><p>统一维护自定义、导入与签名更新策略，并基于实时流量生成优化建议。</p></div><div class="header-actions"><button class="secondary-button" :disabled="loading" @click="load"><RefreshCw :size="17" :class="{ spinning: loading }" /> 刷新</button><button class="primary-button" @click="openCreate"><Plus :size="17" /> 新建策略</button></div></header>
    <p v-if="error" class="inline-alert">{{ error }}</p><p v-if="notice" class="inline-success">{{ notice }}</p>
    <div class="policy-summary"><article class="panel"><span>自定义策略</span><strong>{{ counts.custom }}</strong><small>人工维护，始终保留</small></article><article class="panel"><span>离线导入</span><strong>{{ counts.imported }}</strong><small>原子替换导入来源</small></article><article class="panel"><span>自动更新</span><strong>{{ counts.auto }}</strong><small>{{ settings?.auto_update ? '签名通道已开启' : '当前未开启' }}</small></article><article class="panel"><span>策略总数</span><strong>{{ rules.length }}</strong><small>{{ rules.filter(r => r.enabled).length }} 条已生效</small></article></div>
    <div class="policy-workbench">
      <article class="panel policy-table"><div class="panel-heading"><div><span>检测规则</span><strong>RE2 HOT RELOAD</strong></div><div class="row-actions"><button class="secondary-button compact-button" @click="showImport = true"><Upload :size="14" /> 导入</button><button class="secondary-button compact-button" @click="showUpdate = true"><CloudDownload :size="14" /> 自动更新</button></div></div><div class="table-scroll"><table><thead><tr><th>策略</th><th>来源</th><th>目标</th><th>动作</th><th>优先级</th><th>状态</th><th>操作</th></tr></thead><tbody><tr v-for="rule in rules" :key="rule.id"><td><strong>{{ rule.name }}</strong><small>{{ rule.category }} · {{ rule.description || '无描述' }}</small></td><td><span class="source-badge" :class="rule.source">{{ rule.source }}</span></td><td><code>{{ rule.target }}</code></td><td><span :class="rule.action === 1 ? 'action-block' : 'action-log'">{{ rule.action === 1 ? '拦截' : '记录' }}</span></td><td>{{ rule.priority }}</td><td><button class="switch-control" :class="{ active: rule.enabled }" role="switch" :aria-checked="rule.enabled" @click="toggleRule(rule)"><i></i></button></td><td><div class="row-actions"><button class="icon-button" title="编辑" @click="openEdit(rule)"><Pencil :size="15" /></button><button class="danger-icon" title="删除" @click="removeRule(rule)"><Trash2 :size="15" /></button></div></td></tr></tbody></table><div v-if="!rules.length" class="empty-state">尚未创建策略</div></div></article>
      <aside class="panel optimization-panel"><div class="panel-heading"><div><span>优化建议</span><strong>LIVE RECOMMENDATIONS</strong></div><Sparkles :size="19" /></div><ul><li v-for="item in recommendations" :key="item.id" :class="item.risk"><i></i><div><strong>{{ item.title }}</strong><p>{{ item.reason }}</p><small v-if="item.current !== undefined">当前 {{ item.current }} → 建议 {{ item.recommended }}</small></div><button v-if="item.config_key" class="text-button" @click="applyRecommendation(item)">应用</button></li></ul></aside>
    </div>

    <div v-if="showRule" class="modal-layer"><form class="modal-card" @submit.prevent="saveRule"><div class="modal-heading"><div><p class="eyebrow">CUSTOM RULE</p><h2>{{ editingID ? '编辑策略' : '新建策略' }}</h2></div><button type="button" @click="showRule = false"><X :size="20" /></button></div><label class="field-label">策略名称</label><div class="input-shell"><input v-model.trim="draft.name" maxlength="100" required /></div><div class="policy-form-grid"><div><label class="field-label">分类</label><div class="input-shell"><input v-model.trim="draft.category" maxlength="50" required /></div></div><div><label class="field-label">匹配目标</label><div class="input-shell"><select v-model="draft.target"><option value="all">全部内容</option><option value="uri">URI</option><option value="args">请求参数</option><option value="headers">请求头</option><option value="body">请求体</option><option value="method">请求方法</option></select></div></div><div><label class="field-label">动作</label><div class="input-shell"><select v-model.number="draft.action"><option :value="1">拦截</option><option :value="2">仅记录</option></select></div></div><div><label class="field-label">优先级</label><div class="input-shell"><input v-model.number="draft.priority" type="number" min="1" max="10000" required /></div></div></div><label class="field-label">RE2 正则表达式</label><textarea v-model="draft.pattern" class="policy-textarea code-area" maxlength="1000" required></textarea><p class="field-help">按优先级从小到大执行；不支持回溯引用和前后向断言。</p><label class="field-label">说明</label><div class="input-shell"><input v-model.trim="draft.description" maxlength="255" /></div><div class="form-switches"><label><span><strong>立即启用</strong><small>保存后无需重启即可生效</small></span><button type="button" class="switch-control" :class="{ active: draft.enabled }" @click="draft.enabled = !draft.enabled"><i></i></button></label></div><div class="modal-actions"><button type="button" class="secondary-button" @click="showRule = false">取消</button><button class="primary-button">保存策略</button></div></form></div>
    <div v-if="showImport" class="modal-layer"><div class="modal-card wide-modal"><div class="modal-heading"><div><p class="eyebrow">OFFLINE IMPORT</p><h2>导入规则包</h2></div><button @click="showImport = false"><X :size="20" /></button></div><p class="field-help">导入采用事务替换，仅覆盖上一次离线导入的规则，不影响自定义和自动更新规则。</p><textarea v-model="importJSON" class="policy-textarea import-area"></textarea><div class="modal-actions"><button class="secondary-button" @click="downloadTemplate"><Download :size="15" /> 下载模板</button><button class="primary-button" @click="importRules"><Upload :size="15" /> 校验并导入</button></div></div></div>
    <div v-if="showUpdate" class="modal-layer"><form class="modal-card" @submit.prevent="saveUpdateSettings"><div class="modal-heading"><div><p class="eyebrow">SIGNED UPDATE</p><h2>策略自动更新</h2></div><button type="button" @click="showUpdate = false"><X :size="20" /></button></div><label class="field-label">HTTPS 更新地址</label><div class="input-shell"><input v-model.trim="updateDraft.url" type="url" placeholder="https://rules.example.com/jingshield.json" /></div><label class="field-label">Ed25519 公钥（Base64）</label><div class="input-shell"><input v-model.trim="updateDraft.public_key" placeholder="留空则保留已配置公钥" /></div><p class="field-help">只接受公网 HTTPS、2MB 以内且签名有效的规则包；失败时保留当前规则。</p><label class="field-label">更新间隔（分钟）</label><div class="input-shell"><input v-model.number="updateDraft.interval_minutes" type="number" min="5" max="10080" required /></div><div class="form-switches"><label><span><strong>启用自动更新</strong><small>服务每分钟检查一次是否到期</small></span><button type="button" class="switch-control" :class="{ active: updateDraft.auto_update }" @click="updateDraft.auto_update = !updateDraft.auto_update"><i></i></button></label></div><div v-if="settings" class="update-state"><span>当前版本：{{ settings.last_version || '未更新' }}</span><span>最近更新：{{ settings.last_update || '无' }}</span><span v-if="settings.last_error" class="error-text">{{ settings.last_error }}</span></div><div class="modal-actions"><button type="button" class="secondary-button" :disabled="!updateDraft.url || !settings?.public_key_configured && !updateDraft.public_key" @click="updateNow">立即更新</button><button class="primary-button">保存设置</button></div></form></div>
  </section>
</template>
