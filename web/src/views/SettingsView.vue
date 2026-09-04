<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { DatabaseZap, RefreshCw, Save, ShieldCheck, SlidersHorizontal } from '@lucide/vue'
import { apiRequest, jsonBody } from '../api/client'
import type { ConfigItem, ProtectionStatus } from '../types/api'

const loading = ref(false)
const saving = ref('')
const error = ref('')
const notice = ref('')
const status = ref<ProtectionStatus>({})
const configs = ref<ConfigItem[]>([])
const switches = [
  { key: 'system_status', label: '系统总开关', desc: '关闭后所有防护模块停止判定' },
  { key: 'cc_protection_status', label: 'CC 防护', desc: '启用频率、行为与验证策略' },
  { key: 'xss_protection_status', label: 'XSS 检测', desc: '检测脚本标签与高风险 DOM 载荷' },
  { key: 'sql_protection_status', label: 'SQL 注入检测', desc: '识别查询拼接与数据库特征' },
  { key: 'oversea_ip_status', label: '海外 IP 限制', desc: '依赖 QQWry 归属地数据库' },
]
const fields = computed(() => configs.value.filter((item) => ['cc_visit_count', 'cc_visit_time', 'cc_blacklist_time', 'cc_verify_fail_limit', 'cc_whitelist_time', 'cc_verification_mode', 'log_keep_days'].includes(item.config_key)))
const securityContact = computed(() => configs.value.find((item) => item.config_key === 'security_contact'))

async function load() {
  loading.value = true
  try { [status.value, configs.value] = await Promise.all([apiRequest<ProtectionStatus>('/system/status'), apiRequest<ConfigItem[]>('/config')]); error.value = '' }
  catch (reason) { error.value = reason instanceof Error ? reason.message : '配置加载失败' }
  finally { loading.value = false }
}

async function toggle(key: string) {
  const next = status.value[key] === 1 ? 0 : 1
  saving.value = key
  try { await apiRequest<null>('/system/status', { method: 'PUT', ...jsonBody({ [key]: next }) }); status.value[key] = next; notice.value = '防护状态已更新' }
  catch (reason) { error.value = reason instanceof Error ? reason.message : '状态更新失败' }
  finally { saving.value = '' }
}

async function saveField(item: ConfigItem) {
  saving.value = item.config_key
  try { await apiRequest<null>('/config', { method: 'PUT', ...jsonBody({ config_key: item.config_key, config_value: item.config_value }) }); notice.value = `${item.config_desc || item.config_key}已更新` }
  catch (reason) { error.value = reason instanceof Error ? reason.message : '配置保存失败' }
  finally { saving.value = '' }
}

async function clearCache() {
  if (!window.confirm('确认清理全部进程内防护计数？')) return
  saving.value = 'cache'
  try { await apiRequest<null>('/cache', { method: 'DELETE' }); notice.value = '内存状态缓存已清理' }
  catch (reason) { error.value = reason instanceof Error ? reason.message : '缓存清理失败' }
  finally { saving.value = '' }
}
onMounted(load)
</script>

<template>
  <section class="page-content">
    <header class="page-header"><div><p class="eyebrow">PROTECTION POLICY</p><h1>防护配置</h1><p>调整核心开关与阈值，修改后立即热加载生效。</p></div><button class="secondary-button" :disabled="loading" @click="load"><RefreshCw :size="17" :class="{ spinning: loading }" /> 刷新</button></header>
    <p v-if="error" class="inline-alert">{{ error }}</p><p v-if="notice" class="inline-success">{{ notice }}</p>
    <div class="settings-grid">
      <article class="panel settings-panel">
        <div class="panel-heading"><div><span>引擎开关</span><strong>保护模块运行状态</strong></div><ShieldCheck :size="21" /></div>
        <div class="switch-list"><div v-for="item in switches" :key="item.key" class="switch-row"><div><strong>{{ item.label }}</strong><span>{{ item.desc }}</span></div><button class="switch-control" :class="{ active: status[item.key] === 1 }" :disabled="saving === item.key" role="switch" :aria-checked="status[item.key] === 1" @click="toggle(item.key)"><i></i></button></div></div>
      </article>
      <article class="panel settings-panel">
        <div class="panel-heading"><div><span>策略阈值</span><strong>CC 与日志参数</strong></div><SlidersHorizontal :size="21" /></div>
        <div class="config-list"><label v-for="item in fields" :key="item.config_key"><span><strong>{{ item.config_desc || item.config_key }}</strong><small>{{ item.config_key }}</small></span><div><input v-model="item.config_value" inputmode="numeric" /><button :disabled="saving === item.config_key" title="保存" @click="saveField(item)"><Save :size="16" /></button></div></label><label v-if="securityContact" class="text-config"><span><strong>{{ securityContact.config_desc || '拦截页联系信息' }}</strong><small>security_contact</small></span><div><input v-model="securityContact.config_value" maxlength="200" placeholder="网站安全管理员" /><button :disabled="saving === securityContact.config_key" title="保存" @click="saveField(securityContact)"><Save :size="16" /></button></div></label></div>
      </article>
      <article class="panel maintenance-panel">
        <div class="maintenance-icon"><DatabaseZap :size="24" /></div><div><strong>清理运行时缓存</strong><p>清除当前节点的频率窗口、端口记录和请求行为计数，不删除数据库日志。</p></div><button class="secondary-button" :disabled="saving === 'cache'" @click="clearCache">{{ saving === 'cache' ? '清理中…' : '立即清理' }}</button>
      </article>
    </div>
  </section>
</template>
