<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { Filter, RefreshCw, Search, ShieldAlert } from '@lucide/vue'
import { apiRequest } from '../api/client'
import type { AttackLog, PageData } from '../types/api'

const loading = ref(false)
const error = ref('')
const logs = ref<AttackLog[]>([])
const total = ref(0)
const page = ref(1)
const size = 10
const ip = ref('')
const attackType = ref('')
const types = ['CC攻击', 'XSS攻击', 'SQL注入', 'IP黑名单', '海外IP拦截', '穿盾攻击']

async function load(reset = false) {
  if (reset) page.value = 1
  loading.value = true
  error.value = ''
  const query = new URLSearchParams({ page: String(page.value), size: String(size) })
  if (ip.value.trim()) query.set('ip', ip.value.trim())
  if (attackType.value) query.set('attack_type', attackType.value)
  try {
    const data = await apiRequest<PageData<AttackLog>>(`/attacks?${query}`)
    logs.value = data.list
    total.value = data.total
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '攻击日志加载失败'
  } finally { loading.value = false }
}

function formatTime(value: string) { return new Date(value).toLocaleString('zh-CN', { hour12: false }) }
onMounted(() => load())
</script>

<template>
  <section class="page-content">
    <header class="page-header"><div><p class="eyebrow">ATTACK INTELLIGENCE</p><h1>攻击事件</h1><p>追踪命中规则、来源与累计攻击次数。</p></div><button class="secondary-button" :disabled="loading" @click="load()"><RefreshCw :size="17" :class="{ spinning: loading }" /> 刷新</button></header>
    <div class="filter-bar">
      <div class="filter-field"><Search :size="17" /><input v-model="ip" placeholder="按来源 IP 精确查询" @keyup.enter="load(true)" /></div>
      <div class="filter-field select-field"><Filter :size="17" /><select v-model="attackType"><option value="">全部攻击类型</option><option v-for="type in types" :key="type">{{ type }}</option></select></div>
      <button class="primary-button" @click="load(true)">查询事件</button>
    </div>
    <p v-if="error" class="inline-alert">{{ error }}</p>
    <article class="panel table-panel">
      <div class="table-meta"><span>事件列表</span><strong>共 {{ total.toLocaleString() }} 条记录</strong></div>
      <div class="table-scroll">
        <table>
          <thead><tr><th>来源</th><th>事件类型</th><th>请求</th><th>攻击详情</th><th>次数</th><th>时间</th></tr></thead>
          <tbody>
            <tr v-for="log in logs" :key="log.id">
              <td><strong class="mono">{{ log.ip }}</strong><small>{{ log.ip_location || '未知归属地' }}</small></td>
              <td><span class="event-badge"><ShieldAlert :size="14" />{{ log.attack_type }}</span></td>
              <td><span class="method-badge">{{ log.method }}</span><code>{{ log.uri || '/' }}</code></td>
              <td class="detail-cell">{{ log.attack_detail || '—' }}</td><td><strong>{{ log.attack_count }}</strong></td><td class="nowrap">{{ formatTime(log.created_at) }}</td>
            </tr>
            <tr v-if="!logs.length && !loading"><td colspan="6"><div class="empty-state">当前筛选条件下没有攻击事件</div></td></tr>
          </tbody>
        </table>
      </div>
      <div class="pagination"><button :disabled="page <= 1 || loading" @click="page--; load()">上一页</button><span>第 {{ page }} 页</span><button :disabled="page * size >= total || loading" @click="page++; load()">下一页</button></div>
    </article>
  </section>
</template>
