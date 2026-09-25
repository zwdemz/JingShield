<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from 'vue'
import { ShieldX, X } from '@lucide/vue'
import { apiRequest, jsonBody } from '../api/client'
import { canonicalIPAddress, isBlockableIPAddress, splitIPEntries } from '../utils/ip'
import type { BatchBlockResult } from '../types/api'

const props = withDefaults(defineProps<{ ips?: string[]; endpoint?: string; remote?: boolean }>(), { ips: () => [], endpoint: '/ip-list/block-batch', remote: false })
const emit = defineEmits<{ close: []; completed: [result: BatchBlockResult] }>()
const dialog = ref<HTMLDialogElement | null>(null)
const text = ref(props.ips.join('\n'))
const reason = ref('')
const expireSeconds = ref(3600)
const saving = ref(false)
const error = ref('')
const result = ref<BatchBlockResult | null>(null)
const skippedIPs = computed(() => result.value?.skipped_ips || [])
const entries = computed(() => splitIPEntries(text.value))
const invalidIPs = computed(() => entries.value.filter(ip => !isBlockableIPAddress(ip)))
const unique = computed(() => new Set(entries.value.map(canonicalIPAddress)).size)
const valid = computed(() => entries.value.length > 0 && entries.value.length <= 500 && !invalidIPs.value.length && reason.value.trim().length > 0 && Number.isInteger(expireSeconds.value) && expireSeconds.value >= 0 && expireSeconds.value <= 31536000)

/** Submit only explicit validated literals; response describes local/remote acknowledgement, not syslog. */
async function submit() {
  if (!valid.value || saving.value) return
  const duration = expireSeconds.value === 0 ? '有效期为永久。' : `有效期 ${expireSeconds.value} 秒。`
  if (!window.confirm(`确认${props.remote ? '在联动设备' : '在本机'}封禁 ${unique.value} 个唯一 IP？${duration}白名单地址将跳过。`)) return
  saving.value = true; error.value = ''
  try {
    result.value = await apiRequest<BatchBlockResult>(props.endpoint, { method: 'POST', ...jsonBody({ ips: entries.value, reason: reason.value.trim(), expire_seconds: expireSeconds.value }) })
    emit('completed', result.value)
  } catch (cause) { error.value = cause instanceof Error ? cause.message : '封禁请求失败，请检查状态后再重试' }
  finally { saving.value = false }
}
onMounted(async () => { await nextTick(); dialog.value?.showModal() })
</script>

<template>
  <dialog ref="dialog" class="modal-card batch-dialog" aria-labelledby="batch-heading" @cancel.prevent="!saving && emit('close')" @close="emit('close')">
    <div class="modal-heading"><div><h2 id="batch-heading">{{ remote ? '联动设备批量封禁' : '批量封禁 IP' }}</h2><p class="field-help">单次最多 500 个输入项，仅允许精确 IPv4 / IPv6；重复项也计入上限。</p></div><button type="button" :disabled="saving" aria-label="关闭批量封禁" @click="emit('close')"><X :size="20" /></button></div>
    <p v-if="error" class="inline-alert" role="alert">{{ error }}</p>
    <div v-if="result" role="status" class="batch-result"><p class="inline-success">{{ remote ? '远端已确认' : '本机已处理' }}：封禁 {{ result.blocked }} 个，白名单跳过 {{ result.skipped_whitelist }} 个。</p><p class="field-help">请求 {{ result.requested }} 项 / 去重 {{ result.unique }} 项。Syslog 投递不代表封禁成功。</p><details v-if="skippedIPs.length"><summary>查看跳过的白名单地址</summary><pre>{{ skippedIPs.join('\n') }}</pre></details><button class="primary-button full-button" @click="emit('close')">完成</button></div>
    <form v-else @submit.prevent="submit">
      <label for="batch-ips" class="field-label">IP 列表（每行一个，也可使用逗号分隔）</label><textarea id="batch-ips" v-model="text" class="batch-input mono" rows="8" required :disabled="saving" aria-describedby="batch-count batch-errors" spellcheck="false"></textarea>
      <p id="batch-count" class="field-help" aria-live="polite">输入 {{ entries.length }} / 500 项 · 唯一地址 {{ unique }} 个</p>
      <p id="batch-errors" class="form-error">{{ entries.length > 500 ? '超过单次 500 项上限，请拆分后提交。' : invalidIPs.length ? `无效 IP：${invalidIPs.slice(0, 3).join('、')}${invalidIPs.length > 3 ? '…' : ''}` : '' }}</p>
      <label for="batch-reason" class="field-label">封禁原因（必填）</label><div class="input-shell"><input id="batch-reason" v-model="reason" required maxlength="255" :disabled="saving" placeholder="例如：人工核实重复扫描行为" /></div>
      <label for="batch-expire" class="field-label">封禁秒数（0 为永久，最大 31536000）</label><div class="input-shell"><input id="batch-expire" v-model.number="expireSeconds" type="number" min="0" max="31536000" step="1" required :disabled="saving" /></div>
      <div class="modal-actions"><button type="button" class="secondary-button" :disabled="saving" @click="emit('close')">取消</button><button class="primary-button" type="submit" :disabled="!valid || saving"><ShieldX :size="17" />{{ saving ? '正在提交…' : `确认封禁 ${unique} 个 IP` }}</button></div>
    </form>
  </dialog>
</template>
