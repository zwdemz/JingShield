<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ExternalLink, Globe2, Pencil, Plus, RefreshCw, Server, Trash2, X } from '@lucide/vue'
import { APIError, apiRequest, jsonBody } from '../api/client'
import type { SiteHealth, SiteItem } from '../types/api'

const loading = ref(false)
const saving = ref(false)
const error = ref('')
const notice = ref('')
const sites = ref<SiteItem[]>([])
const health = reactive<Record<number, SiteHealth | undefined>>({})
const checking = reactive<Record<number, boolean>>({})
const showForm = ref(false)
const editingID = ref<number | null>(null)
const form = reactive({ name: '', host: '', upstream: 'http://127.0.0.1:9000', enabled: true, pass_host: false, tls_skip_verify: false })

async function load() {
  loading.value = true
  try { sites.value = await apiRequest<SiteItem[]>('/sites'); error.value = '' }
  catch (reason) { error.value = reason instanceof Error ? reason.message : '防护站点加载失败' }
  finally { loading.value = false }
}

function openCreate() {
  editingID.value = null
  Object.assign(form, { name: '', host: '', upstream: 'http://127.0.0.1:9000', enabled: true, pass_host: false, tls_skip_verify: false })
  showForm.value = true
}

function openEdit(site: SiteItem) {
  editingID.value = site.id
  Object.assign(form, { name: site.name, host: site.host, upstream: site.upstream, enabled: site.enabled, pass_host: site.pass_host, tls_skip_verify: site.tls_skip_verify })
  showForm.value = true
}

async function save() {
  saving.value = true
  error.value = ''
  const editing = editingID.value !== null
  try {
    await apiRequest<SiteItem>(editing ? `/sites/${editingID.value}` : '/sites', { method: editing ? 'PUT' : 'POST', ...jsonBody(form) })
    notice.value = editing ? '防护站点已更新' : '防护站点已创建；现在只有匹配域名的请求会进入源站'
    showForm.value = false
    await load()
  } catch (reason) { error.value = reason instanceof APIError ? reason.message : '站点保存失败' }
  finally { saving.value = false }
}

async function toggle(site: SiteItem) {
  try {
    await apiRequest<null>(`/sites/${site.id}/status`, { method: 'PUT', ...jsonBody({ enabled: !site.enabled }) })
    site.enabled = !site.enabled
    notice.value = `${site.name} 已${site.enabled ? '启用' : '停用'}`
  } catch (reason) { error.value = reason instanceof Error ? reason.message : '状态更新失败' }
}

async function remove(site: SiteItem) {
  if (!window.confirm(`确认删除防护站点“${site.name}”？删除后该域名将不再转发到源站。`)) return
  try { await apiRequest<null>(`/sites/${site.id}`, { method: 'DELETE' }); notice.value = `${site.name} 已删除`; await load() }
  catch (reason) { error.value = reason instanceof Error ? reason.message : '删除失败' }
}

async function checkHealth(site: SiteItem) {
  checking[site.id] = true
  try {
    health[site.id] = await apiRequest<SiteHealth>(`/sites/${site.id}/health`)
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '源站检测失败'
  } finally {
    checking[site.id] = false
  }
}

function visitURL(site: SiteItem) {
  if (site.host.startsWith('*.')) return ''
  const protocol = window.location.protocol === 'https:' ? 'https:' : 'http:'
  return `${protocol}//${site.host}`
}

function formatTime(value: string) { return new Date(value).toLocaleString('zh-CN', { hour12: false }) }
onMounted(load)
</script>

<template>
  <section class="page-content">
    <header class="page-header"><div><p class="eyebrow">PROTECTED SITES</p><h1>防护站点</h1><p>将访问域名映射到真实源站，匹配后先经过鲸盾检测再转发。</p></div><div class="header-actions"><button class="secondary-button" :disabled="loading" @click="load"><RefreshCw :size="17" :class="{ spinning: loading }" /> 刷新</button><button class="primary-button" @click="openCreate"><Plus :size="17" /> 添加站点</button></div></header>
    <p v-if="error" class="inline-alert">{{ error }}</p><p v-if="notice" class="inline-success">{{ notice }}</p>
    <article v-if="!sites.length && !loading" class="panel site-empty"><div class="site-empty-icon"><Globe2 :size="30" /></div><h2>还没有防护站点</h2><p>添加第一个域名和源站后，未知 Host 将被拒绝，不再默认转发到测试源站。</p><button class="primary-button" @click="openCreate"><Plus :size="17" /> 添加第一个站点</button></article>
    <div v-else class="site-grid">
      <article v-for="site in sites" :key="site.id" class="panel site-card" :class="{ disabled: !site.enabled }">
        <div class="site-card-head"><div class="site-symbol"><Globe2 :size="21" /></div><div><h2>{{ site.name }}</h2><span><i :class="{ online: site.enabled }"></i>{{ site.enabled ? '防护中' : '已停用' }}</span></div><button class="switch-control" :class="{ active: site.enabled }" role="switch" :aria-checked="site.enabled" :title="site.enabled ? '停用站点' : '启用站点'" @click="toggle(site)"><i></i></button></div>
        <dl><div><dt>访问域名</dt><dd><code>{{ site.host }}</code><a v-if="site.enabled && visitURL(site)" :href="visitURL(site)" target="_blank" rel="noopener" title="打开站点"><ExternalLink :size="14" /></a></dd></div><div><dt>真实源站</dt><dd><Server :size="14" /><code>{{ site.upstream }}</code></dd></div><div><dt>Host 策略</dt><dd>{{ site.pass_host ? '透传访问域名' : '改写为源站 Host' }}<span v-if="site.tls_skip_verify" class="risk-badge">自签名 TLS</span></dd></div></dl>
        <div v-if="health[site.id]" class="site-health" :class="{ unhealthy: !health[site.id]?.healthy }"><span>{{ health[site.id]?.healthy ? '源站可用' : '源站异常' }}</span><small>{{ health[site.id]?.status_code ? `HTTP ${health[site.id]?.status_code} · ` : '' }}{{ health[site.id]?.latency_ms }} ms</small></div>
        <div class="site-card-foot"><span>更新于 {{ formatTime(site.updated_at) }}</span><div><button title="检测源站" :disabled="checking[site.id]" @click="checkHealth(site)"><RefreshCw :size="16" :class="{ spinning: checking[site.id] }" /></button><button title="编辑站点" @click="openEdit(site)"><Pencil :size="16" /></button><button class="danger-icon" title="删除站点" @click="remove(site)"><Trash2 :size="16" /></button></div></div>
      </article>
    </div>

    <div v-if="showForm" class="modal-layer" @mousedown.self="showForm = false">
      <form class="modal-card" @submit.prevent="save">
        <div class="modal-heading"><div><p class="eyebrow">{{ editingID ? 'EDIT SITE' : 'NEW SITE' }}</p><h2>{{ editingID ? '编辑防护站点' : '添加防护站点' }}</h2></div><button type="button" aria-label="关闭" @click="showForm = false"><X :size="20" /></button></div>
        <label class="field-label" for="site-name">站点名称</label><div class="input-shell"><input id="site-name" v-model.trim="form.name" required maxlength="100" placeholder="例如 公司官网" /></div>
        <label class="field-label" for="site-host">防护域名</label><div class="input-shell"><input id="site-host" v-model.trim="form.host" required maxlength="255" placeholder="www.example.com 或 *.example.com" /></div><p class="field-help">请将该域名的 DNS 指向鲸盾入口；这里不填写 http:// 和路径。</p>
        <label class="field-label" for="site-upstream">真实源站</label><div class="input-shell"><input id="site-upstream" v-model.trim="form.upstream" required maxlength="2048" placeholder="http://127.0.0.1:9000" /></div><p class="field-help">源站应限制为仅允许鲸盾节点访问，避免绕过防护。</p>
        <div class="form-switches"><label><span><strong>立即启用</strong><small>保存后开始接收匹配 Host 的流量</small></span><button type="button" class="switch-control" :class="{ active: form.enabled }" role="switch" :aria-checked="form.enabled" @click="form.enabled = !form.enabled"><i></i></button></label><label><span><strong>透传 Host</strong><small>向源站保留用户访问的域名</small></span><button type="button" class="switch-control" :class="{ active: form.pass_host }" role="switch" :aria-checked="form.pass_host" @click="form.pass_host = !form.pass_host"><i></i></button></label><label><span><strong>允许自签名源站证书</strong><small>降低源站 TLS 校验强度，仅限可信内网服务</small></span><button type="button" class="switch-control" :class="{ active: form.tls_skip_verify }" role="switch" :aria-checked="form.tls_skip_verify" @click="form.tls_skip_verify = !form.tls_skip_verify"><i></i></button></label></div>
        <div class="modal-actions"><button type="button" class="secondary-button" @click="showForm = false">取消</button><button class="primary-button" type="submit" :disabled="saving">{{ saving ? '正在保存…' : '保存站点' }}</button></div>
      </form>
    </div>
  </section>
</template>
