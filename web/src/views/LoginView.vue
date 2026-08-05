<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowRight, Eye, EyeOff, LockKeyhole, Radar, ShieldCheck, UserRound } from '@lucide/vue'
import { APIError } from '../api/client'
import { useAuthStore } from '../stores/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const username = ref('admin')
const password = ref('')
const showPassword = ref(false)
const error = ref('')

async function submit() {
  error.value = ''
  try {
    const session = await auth.login(username.value.trim(), password.value)
    if (session.must_change_password) {
      await router.replace({ name: 'change-password' })
      return
    }
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
    await router.replace(redirect)
  } catch (reason) {
    error.value = reason instanceof APIError ? reason.message : '登录失败，请稍后重试'
  }
}
</script>

<template>
  <main class="auth-page">
    <section class="auth-story" aria-label="产品介绍">
      <div class="brand-lockup">
        <span class="brand-mark"><ShieldCheck :size="28" /></span>
        <div><strong>捷云鲸盾</strong><small>JIEYUN JINGSHIELD</small></div>
      </div>
      <div class="auth-story-copy">
        <p class="eyebrow"><span class="pulse-dot"></span> 防护节点在线</p>
        <h1>看清每一次请求，<br />守住每一道边界。</h1>
        <p>聚合 CC、注入、IP 策略与访问态势，让安全决策更快一步。</p>
      </div>
      <div class="signal-board" aria-hidden="true">
        <div class="signal-orbit orbit-a"></div><div class="signal-orbit orbit-b"></div>
        <Radar :size="56" />
        <span class="signal-point point-a"></span><span class="signal-point point-b"></span><span class="signal-point point-c"></span>
      </div>
      <ul class="auth-features">
        <li><strong>8</strong><span>种 CC 验证模式</span></li>
        <li><strong>24h</strong><span>攻击趋势追踪</span></li>
        <li><strong>实时</strong><span>策略热更新</span></li>
      </ul>
    </section>

    <section class="auth-panel">
      <form class="auth-card" @submit.prevent="submit">
        <div class="auth-heading">
          <p class="eyebrow">SECURITY CONSOLE</p>
          <h2>登录控制台</h2>
          <p>使用管理员账号进入防护中心</p>
        </div>

        <label class="field-label" for="username">管理员账号</label>
        <div class="input-shell">
          <UserRound :size="18" />
          <input id="username" v-model="username" autocomplete="username" maxlength="50" required placeholder="请输入账号" />
        </div>

        <label class="field-label" for="password">密码</label>
        <div class="input-shell">
          <LockKeyhole :size="18" />
          <input id="password" v-model="password" :type="showPassword ? 'text' : 'password'" autocomplete="current-password" maxlength="255" required placeholder="请输入密码" />
          <button class="icon-button" type="button" :aria-label="showPassword ? '隐藏密码' : '显示密码'" @click="showPassword = !showPassword">
            <EyeOff v-if="showPassword" :size="18" /><Eye v-else :size="18" />
          </button>
        </div>

        <p v-if="error" class="form-error" role="alert">{{ error }}</p>
        <button class="primary-button auth-submit" type="submit" :disabled="auth.loading">
          <span>{{ auth.loading ? '正在验证…' : '安全登录' }}</span><ArrowRight :size="18" />
        </button>
        <p class="auth-footnote"><LockKeyhole :size="14" /> 会话受 HttpOnly Cookie 与 CSRF 双重保护</p>
      </form>
    </section>
  </main>
</template>
