/** Browser interaction regression suite. All API responses are explicit mocks, not backend validation.
 * Run with Vite started: node tests/operations-ui.smoke.mjs
 * PLAYWRIGHT_MODULE optionally points to a provisioned Playwright module; no project dependency is added.
 */
import assert from 'node:assert/strict'
import { mkdir } from 'node:fs/promises'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const modulePath = process.env.PLAYWRIGHT_MODULE
const { chromium } = await import(modulePath ? pathToFileURL(modulePath).href : 'playwright')
const base = process.env.UI_BASE_URL || 'http://127.0.0.1:5179/admin'
const artifacts = process.env.UI_ARTIFACTS || path.resolve('test-artifacts')
await mkdir(artifacts, { recursive: true })
const browser = await chromium.launch({ headless: true, ...(process.env.UI_BROWSER_EXECUTABLE ? { executablePath: process.env.UI_BROWSER_EXECUTABLE } : {}) })
const context = await browser.newContext({ viewport: { width: 1280, height: 720 }, reducedMotion: 'reduce' })
const page = await context.newPage()
const errors = []
const requests = []
const results = []
page.on('pageerror', error => errors.push(error.message))
page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
page.on('dialog', dialog => dialog.accept())
const check = (name, condition) => { assert.ok(condition, name); results.push(name) }
const screenshot = async (filename) => {
  await page.evaluate(() => window.scrollTo(0, 0))
  await page.screenshot({ path: path.join(artifacts, filename), fullPage: true })
}
const now = '2026-09-25T03:00:00Z'
// Match internal/config/protection.go; presets never alter the independent master switch.
const engineNames = { cc_protection_status: 'CC 频率防护', xss_protection_status: 'XSS 防护', sql_protection_status: 'SQL 注入防护', path_traversal_protection_status: '路径穿越防护', ssrf_protection_status: 'SSRF 防护', xxe_protection_status: 'XXE 防护', scanner_protection_status: '行为扫描防护', policy_protection_status: '自定义策略引擎' }
const standard = { ...Object.fromEntries(Object.keys(engineNames).map(key => [key, '1'])), cc_visit_count: '100', cc_visit_time: '60', behavior_window_seconds: '300', behavior_threshold: '8', behavior_block_seconds: '600', behavior_mode: 'block' }
let protection = {
  profile: 'standard',
  profiles: [
    { id: 'low', label: '兼容优先', description: '保留语义检测，放宽频率阈值，行为扫描仅观察。', values: { ...standard, cc_visit_count: '300', behavior_threshold: '16', behavior_block_seconds: '300', behavior_mode: 'observe' } },
    { id: 'standard', label: '标准防护', description: '语义检测与行为拦截同时启用，适合日常运行。', values: { ...standard } },
    { id: 'strict', label: '严格防护', description: '降低频率和行为触发阈值；启用前评估 NAS 并发业务。', values: { ...standard, cc_visit_count: '60', behavior_threshold: '4', behavior_block_seconds: '1800' } },
  ],
  values: { ...standard, system_status: '1' },
}
const configDefaults = { cc_blacklist_time: '3600', cc_verify_fail_limit: '10', cc_whitelist_time: '1800', cc_verification_mode: '1', log_keep_days: '30', security_contact: '网站安全管理员' }
const configDescriptions = { cc_visit_count: 'CC 触发次数', cc_visit_time: 'CC 触发时间窗口（秒）', cc_blacklist_time: '临时黑名单时长（秒）', cc_verify_fail_limit: '验证失败次数上限', cc_whitelist_time: '验证通过后白名单时长（秒）', cc_verification_mode: '验证模式 1–8', log_keep_days: '日志保留天数', security_contact: '拦截页联系信息' }
const settings = () => ({ ...protection, engines: Object.entries(engineNames).map(([key, label]) => ({ key, label, enabled: protection.values[key] === '1' })) })
let syslog = { enabled: true, transport: 'tls', address: 'logs.example.com:6514', server_name: '', facility: 16, timeout_seconds: 3, max_retries: 3, queue_capacity: 1000 }
let syslogStatus = { running: true, queued: 6, failed: 2, queue_capacity: 1000, sent_total: 48, retried_total: 3, dropped_total: 0, last_success: now, last_error: '', delivery_semantics: 'transport_only_at_least_once', counter_scope: 'current_process' }
let linkage = { enabled: true, device_vendor: 'jingshield', protocol: 'jingshield-v1', device_type: 'waf', endpoint: 'https://peer.example.com:8443', secret_env: 'JINGSHIELD_LINKAGE_API_KEY', timeout_seconds: 5, source_id: 'ui_test_waf' }
let linkageStatus = { compatible: false, last_probe: '', last_success: '', last_error: '', last_result: null, integration_mode: 'same_protocol_adapter_only' }
let resources = { hostname: 'nas-test', os: 'linux', platform: 'amd64', uptime_seconds: 9622, cpu_percent: 18, memory_used_bytes: 1000000, memory_total_bytes: 4000000, memory_percent: 25, disk_used_bytes: 1000000, disk_total_bytes: 10000000, disk_percent: 10, log_size_bytes: 1024, request_rate: 12, thresholds: { cpu_percent: 80, memory_percent: 85, disk_percent: 85, log_size_mb: 512, request_rate: 600 }, alerts: [] }
let delayOldRequest = false
const log = ip => ({ id: ip === '192.0.2.1' ? 1 : 2, event_id: `event-${ip}`, ip, ip_location: '测试网络', host: 'nas.example.test', uri: '/.git/config', method: 'GET', attack_type: '扫描探测', severity: 4, attack_detail: '敏感路径行为命中', request_packet: 'GET /.git/config HTTP/1.1', attack_count: 8, status: 1, created_at: now })

await page.route('**/api/v1/**', async route => {
  const request = route.request()
  const url = new URL(request.url())
  const endpoint = url.pathname.replace('/api/v1', '')
  const method = request.method()
  const body = request.postDataJSON()
  requests.push({ endpoint, method, body, query: Object.fromEntries(url.searchParams) })
  let data = null
  if (endpoint === '/auth/me') data = { user_id: 1, username: 'ui-test', role: 'admin', csrf_token: 'mock-only', must_change_password: false }
  else if (endpoint === '/system/resources') data = resources
  else if (endpoint === '/system/alert-thresholds') { resources = { ...resources, thresholds: body }; data = null }
  else if (endpoint === '/dashboard/stats') data = { total_requests: 120, total_ips: 12, blocked_requests: 4, blacklist_ips: 1, whitelist_ips: 2 }
  else if (endpoint === '/dashboard/trend') data = { trend: [] }
  else if (endpoint === '/dashboard/top-ips') data = []
  else if (endpoint === '/system/status') data = { system_status: 1, cc_protection_status: 1, xss_protection_status: 1, sql_protection_status: 1, oversea_ip_status: 0 }
  else if (endpoint === '/integration') data = { enabled: false, key_configured: false, key_masked: '', header: 'X-API-Key', endpoints: [] }
  else if (endpoint === '/integration/device-settings') data = { auto_block_enabled: false, auto_block_severity: 8, auto_block_seconds: 3600 }
  else if (endpoint === '/device-events') data = { list: [], total: 0, page: 1, size: 6 }
  else if (endpoint === '/access-logs') data = { list: [], total: 0, page: 1, size: 12 }
  else if (endpoint === '/system/waf-status') data = { waf_enabled: protection.values.system_status === '1', started_at: now, uptime_seconds: 9622, state_backend: 'redis', shared_state: true, metrics: { evaluated_total: 12463, blocked_total: 154, challenged_total: 21, evaluation_nanoseconds_total: 12560000, access_queue_depth: 5, attack_queue_depth: 2, access_queue_capacity: 1000, attack_queue_capacity: 256, audit_failed_total: 0, audit_dropped_total: 0, behavior: { checked_total: 12463, probe_total: 182, matched_total: 32, observed_total: 21, blocked_total: 11, state_errors_total: 0, state_available: true } }, protection: settings(), sites: { total: 3, enabled: 2 }, server_time: now }
  else if (endpoint === '/system/syslog') {
    if (method === 'PUT') syslog = body
    data = { config: syslog, status: syslogStatus }
  } else if (endpoint === '/system/syslog/sync') { syslogStatus = { ...syslogStatus, queued: 8, failed: 0 }; data = syslogStatus }
  else if (endpoint === '/system/linkage') {
    if (method === 'PUT') { linkage = body; linkageStatus.compatible = false }
    data = { config: linkage, status: linkageStatus }
  } else if (endpoint === '/system/linkage/probe') { linkageStatus = { ...linkageStatus, compatible: true, last_probe: now }; data = { protocol: 'jingshield-v1', device_type: linkage.device_type, capabilities: ['block-batch', 'whitelist-sync'], max_batch_size: 500 } }
  else if (endpoint === '/system/linkage/whitelist/preview') data = { source: linkage.source_id, count: 1, rules: ['192.0.2.0/24'], digest: 'a'.repeat(64) }
  else if (endpoint === '/system/linkage/whitelist/sync') { data = { source: linkage.source_id, revision: 1790000000000000, count: 1, digest: body.expected_digest }; linkageStatus.last_whitelist = data }
  else if (endpoint === '/protection/settings') {
    if (method === 'PUT') {
      if (body.values && Object.values(body.values).some(value => typeof value !== 'string')) {
        await route.fulfill({ status: 400, json: { code: -3, message: '防护设置格式非法', data: null } })
        return
      }
      if (body.profile) protection.values = { ...protection.values, ...protection.profiles.find(profile => profile.id === body.profile).values }
      if (body.values) protection.values = { ...protection.values, ...body.values }
      protection.profile = protection.profiles.find(profile => Object.entries(profile.values).every(([key, value]) => protection.values[key] === value))?.id || 'custom'
    }
    data = settings()
  } else if (endpoint === '/config') {
    if (method === 'PUT') {
      if (Object.hasOwn(protection.values, body.config_key)) {
        protection.values[body.config_key] = body.config_value
        protection.profile = protection.profiles.find(profile => Object.entries(profile.values).every(([key, value]) => protection.values[key] === value))?.id || 'custom'
      } else configDefaults[body.config_key] = body.config_value
    }
    data = Object.entries({ ...configDefaults, ...protection.values }).map(([config_key, config_value], index) => ({ id: index + 1, config_key, config_value, config_desc: configDescriptions[config_key] || config_key, created_at: now, updated_at: now }))
  }
  else if (endpoint === '/attacks') {
    const ip = url.searchParams.get('ip') || '192.0.2.1'
    if (delayOldRequest && ip === '192.0.2.1') await new Promise(resolve => setTimeout(resolve, 350))
    data = { list: [log(ip)], total: 1, page: 1, size: 20 }
  } else if (endpoint === '/attacks/ip-summary') {
    const ip = url.searchParams.get('ip')
    if (delayOldRequest && ip === '192.0.2.1') await new Promise(resolve => setTimeout(resolve, 500))
    data = { ip, records: 3, attack_count: 24, blocked_records: 2, observed_records: 1, max_severity: 4, first_seen: now, last_seen: now, attack_types: [{ attack_type: '扫描探测', count: 24 }], hosts: [{ host: 'nas.example.test', count: 24 }], list_status: 'none' }
  } else if (endpoint.endsWith('/block-batch')) {
    const unique = new Set(body.ips).size
    data = { requested: body.ips.length, unique, blocked: unique, skipped_whitelist: 0, skipped_ips: null }
    if (endpoint.startsWith('/system/')) linkageStatus.last_result = data
  } else if (endpoint === '/ip-list') data = { list: [], total: 0, page: 1, size: 10 }
  else if (endpoint === '/ip-list/received-whitelist') data = [{ source: 'remote_waf', revision: 1790000000000000, rules: ['198.51.100.0/24'] }]
  else throw new Error(`Unexpected mocked API: ${method} ${endpoint}`)
  try { await route.fulfill({ json: { code: 0, message: 'ok', data } }) } catch (error) { if (!request.url().includes('/attacks')) throw error }
})

try {
  await page.goto(`${base}/waf-status`)
  await page.waitForURL(`${base}/system-status`)
  check('old WAF status URL redirects to system status', true)
  await page.getByText('多节点共享状态', { exact: true }).waitFor()
  check('host resources moved to system status', await page.getByText('本机运行环境', { exact: true }).count() === 1)
  await page.getByRole('button', { name: '告警阈值' }).click()
  await page.locator('.threshold-modal input').first().fill('75')
  await page.getByRole('button', { name: '应用阈值' }).click()
  check('system status retains editable resource thresholds', requests.some(request => request.endpoint === '/system/alert-thresholds' && request.method === 'PUT' && request.body.cpu_percent === 75))
  await page.getByLabel('每 15 秒刷新状态').uncheck()
  const titleMetrics = await page.locator('.page-header').evaluate(node => ({ headerHeight: node.getBoundingClientRect().height, titleFont: getComputedStyle(node.querySelector('h1')).fontSize }))
  check('desktop compact heading is 20px and header at most 80px', titleMetrics.titleFont === '20px' && titleMetrics.headerHeight <= 80)
  await screenshot('system-status-desktop.png')
  await page.setViewportSize({ width: 375, height: 812 })
  check('system status has no mobile horizontal overflow', await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
  await screenshot('system-status-mobile.png')
  await page.setViewportSize({ width: 1280, height: 720 })
  await page.goto(`${base}/`)
  await page.getByText('今日安全态势', { exact: true }).waitFor()
  check('security overview no longer duplicates host resources', await page.getByText('本机运行环境', { exact: true }).count() === 0)
  await page.goto(`${base}/integration`)
  await page.locator('#linkage-url').waitFor()
  check('syslog and peer linkage are on integration page', await page.locator('#syslog-address').count() === 1 && await page.locator('#linkage-url').count() === 1)
  const remoteButton = page.getByRole('button', { name: '联动封禁 IP（上限 500）' })
  check('unverified protocol cannot issue remote blocking', await remoteButton.isDisabled())
  await page.locator('#linkage-url').fill('https://unsaved.example.com')
  await page.locator('#syslog-address').fill('logs2.example.com:6514')
  await page.getByRole('button', { name: '保存 Syslog 配置' }).click()
  await page.getByText('Syslog 配置已保存。', { exact: false }).waitFor()
  check('saving syslog preserves unsaved linkage draft', await page.locator('#linkage-url').inputValue() === 'https://unsaved.example.com')
  check('syslog PUT uses edited address', requests.some(request => request.endpoint === '/system/syslog' && request.method === 'PUT' && request.body.address === 'logs2.example.com:6514'))
  await page.getByLabel('同时重试失败项（可能重复投递）').check()
  await page.getByRole('button', { name: '立即同步待发送日志' }).click()
  await page.getByText('已请求重新处理失败队列', { exact: false }).waitFor()
  check('explicit failed queue retry is sent', requests.some(request => request.endpoint === '/system/syslog/sync' && request.body.retry_failed === true))
  await page.locator('#linkage-url').fill(linkage.endpoint)
  await page.getByRole('button', { name: '探测同协议能力' }).click()
  await page.getByText('握手兼容', { exact: true }).waitFor()
  check('successful capability handshake unlocks remote blocking', await remoteButton.isEnabled())
  await page.getByRole('button', { name: '预览本机白名单' }).click()
  await page.getByText('待下发：1 条，来源 ui_test_waf').waitFor()
  check('whitelist preview displays exact source and rule count', await page.getByText('192.0.2.0/24', { exact: true }).count() === 1)
  await page.getByRole('button', { name: '确认并下发快照' }).click()
  await page.getByText('对端已确认接收来源 ui_test_waf', { exact: false }).waitFor()
  check('whitelist push submits the preview digest after confirmation', requests.some(request => request.endpoint === '/system/linkage/whitelist/sync' && request.body.expected_digest === 'a'.repeat(64)))
  await screenshot('integration-desktop.png')
  await page.setViewportSize({ width: 375, height: 812 })
  check('integration page has no horizontal viewport overflow at 375px', await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
  await screenshot('integration-mobile.png')

  await page.setViewportSize({ width: 1280, height: 720 })
  await page.goto(`${base}/settings`)
  await page.getByRole('switch', { name: 'WAF 总开关' }).waitFor()
  await page.getByText('引擎实际运行状态', { exact: true }).waitFor()
  const optionPalette = await page.locator('#behavior-mode option').first().evaluate(option => ({
    foreground: getComputedStyle(option).color,
    background: getComputedStyle(option).backgroundColor,
  }))
  check('native dropdown options use dark text on a light popup', optionPalette.foreground === 'rgb(23, 38, 58)' && optionPalette.background === 'rgb(247, 250, 252)')
  check('enabled backend master switch renders enabled', await page.getByRole('switch', { name: 'WAF 总开关' }).getAttribute('aria-checked') === 'true')
  await page.locator('#behavior_threshold').fill('20')
  await page.getByRole('button', { name: '保存行为策略' }).click()
  await page.getByText('行为检测参数已更新', { exact: true }).waitFor({ timeout: 3000 })
  check('edited behavior threshold persists as a string', protection.values.behavior_threshold === '20' && requests.some(request => request.endpoint === '/protection/settings' && request.method === 'PUT' && request.body.values?.behavior_threshold === '20'))
  await page.getByLabel('临时黑名单时长（秒）', { exact: true }).fill('7200')
  await page.getByLabel('CC 触发次数', { exact: true }).fill('175')
  await page.getByRole('button', { name: /^严格防护 / }).click()
  await page.getByText('当前：严格', { exact: true }).waitFor()
  check('profile application does not alter global master switch', protection.values.system_status === '1')
  check('strict profile refreshes the affected CC field from persisted settings', await page.getByLabel('CC 触发次数', { exact: true }).inputValue() === '60')
  check('profile application preserves unrelated unsaved CC draft', await page.getByLabel('临时黑名单时长（秒）', { exact: true }).inputValue() === '7200')
  await page.locator('#behavior_threshold').fill('99')
  await page.getByLabel('CC 触发次数', { exact: true }).fill('61')
  await page.getByRole('switch', { name: 'SQL 注入防护' }).click()
  await page.getByText('当前：自定义', { exact: true }).waitFor()
  check('single engine toggle persists without resetting other engines', protection.values.sql_protection_status === '0' && protection.values.xss_protection_status === '1')
  check('single engine toggle preserves unsaved behavior draft', await page.locator('#behavior_threshold').inputValue() === '99')
  check('single engine toggle preserves unsaved CC count draft', await page.getByLabel('CC 触发次数', { exact: true }).inputValue() === '61')
  await page.getByLabel('CC 触发次数', { exact: true }).fill(protection.values.cc_visit_count)
  const switchBox = await page.getByRole('switch', { name: 'SQL 注入防护' }).boundingBox()
  check('engine switches have at least 44px target height', switchBox.height >= 44)
  await page.getByRole('button', { name: /^严格防护 / }).click()
  await page.getByText('当前：严格', { exact: true }).waitFor()
  await page.locator('#behavior_threshold').fill('99')
  await page.getByLabel('CC 触发次数', { exact: true }).fill('61')
  await page.getByRole('button', { name: '保存 CC 触发次数', exact: true }).click()
  await page.getByText('当前：自定义', { exact: true }).waitFor()
  check('individual CC save refreshes custom profile without overwriting unrelated drafts', protection.profile === 'custom' && protection.values.cc_visit_count === '61' && await page.locator('#behavior_threshold').inputValue() === '99' && await page.getByLabel('临时黑名单时长（秒）', { exact: true }).inputValue() === '7200')
  await screenshot('engines-desktop.png')
  await page.setViewportSize({ width: 375, height: 812 })
  check('engine settings has no mobile horizontal overflow', await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
  await screenshot('engines-mobile.png')

  await page.setViewportSize({ width: 1280, height: 720 })
  await page.goto(`${base}/attacks`)
  await page.getByRole('button', { name: '检索 192.0.2.1 风险画像' }).waitFor()
  await page.locator('summary').filter({ hasText: '行为检测运行指标' }).click()
  await page.getByText('累计行为检查', { exact: true }).waitFor()
  check('behavior metrics are available inside attack events', true)
  await page.getByRole('button', { name: '批量封禁 IP', exact: true }).click()
  await page.locator('#batch-reason').fill('mock behavior review')
  await page.locator('#batch-ips').fill(Array(501).fill('192.0.2.1').join('\n'))
  check('duplicate entries cannot bypass raw 500-item limit', await page.getByRole('button', { name: '确认封禁 1 个 IP' }).isDisabled())
  const ips = Array.from({ length: 500 }, (_, index) => `192.0.${Math.floor(index / 250)}.${index % 250 + 1}`)
  await page.locator('#batch-ips').fill([...ips, '198.51.100.1'].join('\n'))
  check('501 submitted entries are rejected before API dispatch', await page.getByRole('button', { name: '确认封禁 501 个 IP' }).isDisabled())
  await page.locator('#batch-ips').fill(ips.join('\n'))
  check('500 valid entries are accepted', await page.getByRole('button', { name: '确认封禁 500 个 IP' }).isEnabled())
  await page.getByRole('button', { name: '确认封禁 500 个 IP' }).click()
  await page.getByRole('button', { name: '完成', exact: true }).waitFor()
  check('500 entry batch submitted as one request', requests.filter(request => request.endpoint === '/ip-list/block-batch').length === 1 && requests.find(request => request.endpoint === '/ip-list/block-batch').body.ips.length === 500)
  await page.getByRole('button', { name: '完成', exact: true }).click()
  await page.getByLabel('来源 IP', { exact: true }).fill('999.2.3.4')
  await page.getByRole('button', { name: '查询事件', exact: true }).click()
  await page.getByText('请输入完整的 IPv4 或 IPv6 地址', { exact: true }).waitFor()
  check('invalid IP produces explicit validation error', true)
  delayOldRequest = true
  await page.getByLabel('来源 IP', { exact: true }).fill('192.0.2.1')
  await page.getByLabel('来源 IP', { exact: true }).press('Enter')
  await page.getByLabel('来源 IP', { exact: true }).fill('192.0.2.2')
  await page.getByLabel('来源 IP', { exact: true }).press('Enter')
  await page.getByText('IP 风险画像 · 192.0.2.2', { exact: true }).waitFor()
  await page.waitForTimeout(650)
  check('late old search cannot overwrite newest IP summary', await page.getByText('IP 风险画像 · 192.0.2.1', { exact: true }).count() === 0)
  check('late old search cannot overwrite newest log rows', await page.getByRole('button', { name: '检索 192.0.2.2 风险画像' }).count() === 1)
  await screenshot('attacks-desktop.png')
  await page.setViewportSize({ width: 375, height: 812 })
  check('attack table scrolls within page instead of expanding viewport', await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
  await screenshot('attacks-mobile.png')
  await page.goto(`${base}/access`)
  await page.locator('summary').filter({ hasText: '请求与审计追加状态' }).click()
  await page.getByText('访问日志队列', { exact: true }).waitFor()
  check('audit append queue is available inside access audit', true)
  const validation = await page.evaluate(async () => {
    const ip = await import('/admin/src/utils/ip.ts')
    return {
      exact: ['192.0.2.1', '2001:db8::1', '::ffff:192.0.2.1'].every(ip.isIPAddress),
      invalid: ['192.0.2.999', '192.168.01.1', '[::1]', 'fe80::1%eth0', 'host.example'].every(value => !ip.isIPAddress(value)),
      prefixes: ['', '192.', '192.168.', '2001:db8:'].every(value => !ip.validateIPFilter(value, 'prefix')),
      cidr: ['192.0.2.0/24', '2001:db8::/32'].every(value => !ip.validateIPFilter(value, 'cidr')),
      forbidden: ['0.0.0.0', '224.0.0.1', '::', 'ff02::1', '::ffff:224.0.0.1'].every(value => !ip.isBlockableIPAddress(value)),
      canonical: ip.canonicalIPAddress('2001:0db8:0:0:0:0:0:1') === ip.canonicalIPAddress('2001:db8::1'),
    }
  })
  for (const [name, passed] of Object.entries(validation)) check(`IP validation ${name}`, passed)
  check('no browser console errors or uncaught exceptions', errors.length === 0)
  console.log(JSON.stringify({ passed: results.length, results, titleMetrics, browserErrors: errors, artifacts, scope: 'mock API browser interactions only' }, null, 2))
} finally {
  await browser.close()
}
