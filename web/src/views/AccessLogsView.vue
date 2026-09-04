<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RefreshCw, Search } from '@lucide/vue'
import { apiRequest } from '../api/client'
import type { AccessLog, PageData } from '../types/api'

const loading = ref(false)
const error = ref('')
const logs = ref<AccessLog[]>([])
const total = ref(0)
const page = ref(1)
const size = 12
const ip = ref('')

async function load(reset = false) {
  if (reset) page.value = 1
  loading.value = true
  const query = new URLSearchParams({ page: String(page.value), size: String(size) })
  if (ip.value.trim()) query.set('ip', ip.value.trim())
  try { const data = await apiRequest<PageData<AccessLog>>(`/access-logs?${query}`); logs.value = data.list; total.value = data.total; error.value = '' }
  catch (reason) { error.value = reason instanceof Error ? reason.message : '访问日志加载失败' }
  finally { loading.value = false }
}
function formatTime(value: string) { return new Date(value).toLocaleString('zh-CN', { hour12: false }) }
onMounted(() => load())
</script>

<template>
  <section class="page-content">
    <header class="page-header"><div><p class="eyebrow">ACCESS AUDIT</p><h1>访问审计</h1><p>核对经过防护链的请求、响应状态与耗时。</p></div><button class="secondary-button" :disabled="loading" @click="load()"><RefreshCw :size="17" :class="{ spinning: loading }" /> 刷新</button></header>
    <div class="filter-bar"><div class="filter-field"><Search :size="17" /><input v-model="ip" placeholder="按来源 IP 精确查询" @keyup.enter="load(true)" /></div><button class="primary-button" @click="load(true)">查询访问</button></div>
    <p v-if="error" class="inline-alert">{{ error }}</p>
    <article class="panel table-panel">
      <div class="table-meta"><span>请求流水</span><strong>共 {{ total.toLocaleString() }} 条记录</strong></div>
      <div class="table-scroll"><table><thead><tr><th>来源 IP</th><th>请求</th><th>主机</th><th>状态</th><th>响应耗时</th><th>时间</th></tr></thead><tbody>
        <tr v-for="log in logs" :key="log.id"><td><strong class="mono">{{ log.ip }}</strong></td><td><span class="method-badge">{{ log.method }}</span><code>{{ log.uri || '/' }}</code></td><td>{{ log.host || '—' }}</td><td><span class="status-code" :class="{ error: log.status >= 400 }">{{ log.status }}</span></td><td>{{ Number(log.response_time).toFixed(1) }} ms</td><td class="nowrap">{{ formatTime(log.created_at) }}</td></tr>
        <tr v-if="!logs.length && !loading"><td colspan="6"><div class="empty-state">暂无访问日志</div></td></tr>
      </tbody></table></div>
      <div class="pagination"><button :disabled="page <= 1 || loading" @click="page--; load()">上一页</button><span>第 {{ page }} 页</span><button :disabled="page * size >= total || loading" @click="page++; load()">下一页</button></div>
    </article>
  </section>
</template>
