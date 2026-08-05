<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
	Activity, Cable, FileClock, Gauge, Globe2, ListFilter, LogOut, Menu, Settings2, ShieldCheck, ShieldEllipsis, UserRoundCog, X,
} from '@lucide/vue'
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()
const mobileOpen = ref(false)
const navItems = [
  { name: 'dashboard', label: '安全态势', icon: Gauge },
  { name: 'attacks', label: '攻击事件', icon: Activity },
  { name: 'access', label: '访问审计', icon: FileClock },
  { name: 'sites', label: '防护站点', icon: Globe2 },
  { name: 'ip-list', label: 'IP 策略', icon: ListFilter },
  { name: 'policies', label: '策略中心', icon: ShieldEllipsis },
  { name: 'settings', label: '防护配置', icon: Settings2 },
	{ name: 'users', label: '用户管理', icon: UserRoundCog },
	{ name: 'integration', label: 'API 联动', icon: Cable },
]

async function logout() {
  await auth.logout()
  await router.replace({ name: 'login' })
}
</script>

<template>
  <div class="admin-shell">
    <aside class="sidebar" :class="{ open: mobileOpen }">
      <div class="sidebar-brand">
        <span class="brand-mark"><ShieldCheck :size="24" /></span>
        <div><strong>捷云鲸盾</strong><small>SECURITY OPS</small></div>
        <button class="mobile-close" aria-label="关闭菜单" @click="mobileOpen = false"><X :size="20" /></button>
      </div>
      <nav class="main-nav" aria-label="主导航">
        <RouterLink v-for="item in navItems" :key="item.name" :to="{ name: item.name }" @click="mobileOpen = false">
          <component :is="item.icon" :size="19" /><span>{{ item.label }}</span><i></i>
        </RouterLink>
      </nav>
      <div class="sidebar-health">
        <div class="health-ring"><ShieldCheck :size="24" /></div>
        <div><span>防护引擎</span><strong><i class="pulse-dot"></i> 运行中</strong></div>
      </div>
      <div class="sidebar-user">
        <span class="avatar">{{ auth.user?.username.slice(0, 1).toUpperCase() }}</span>
        <div><strong>{{ auth.user?.username }}</strong><small>系统管理员</small></div>
        <button aria-label="退出登录" title="退出登录" @click="logout"><LogOut :size="18" /></button>
      </div>
    </aside>
    <button v-if="mobileOpen" class="sidebar-backdrop" aria-label="关闭菜单" @click="mobileOpen = false"></button>
    <section class="workspace">
      <header class="topbar">
        <button class="mobile-menu" aria-label="打开菜单" @click="mobileOpen = true"><Menu :size="22" /></button>
        <div class="breadcrumb"><span>鲸盾控制台</span><b>/</b><strong>{{ navItems.find((item) => item.name === route.name)?.label || '安全中心' }}</strong></div>
        <div class="topbar-status"><span class="pulse-dot"></span> 节点在线</div>
      </header>
      <main class="page-stage"><RouterView /></main>
    </section>
  </div>
</template>
