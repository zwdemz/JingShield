export interface APIEnvelope<T> {
  code: number
  message: string
  data: T
}

export interface SessionUser {
  user_id: number
  username: string
  role: string
  csrf_token: string
  must_change_password: boolean
}

export interface DashboardStats {
  total_requests: number
  total_ips: number
  blocked_requests: number
  blacklist_ips: number
  whitelist_ips: number
}

export interface TrendPoint {
  hour: string
  count: number
}

export interface TopIP {
  ip: string
  count: number
}

export interface PageData<T> {
  list: T[]
  total: number
  page: number
  size: number
}

export interface AttackLog {
  id: number
  event_id: string
  ip: string
  ip_location: string
  host: string
  uri: string
  method: string
  attack_type: string
  severity: 1 | 2 | 3 | 4 | 5
  attack_detail: string
  request_packet: string
  attack_count: number
  status: number
  created_at: string
}

export interface AccessLog {
  id: number
  ip: string
  host: string
  uri: string
  method: string
  user_agent: string
  referer: string
  status: number
  response_time: number
  created_at: string
}

export interface LoginLog {
  id: number
  user_id: number
  login_ip: string
  login_time: string
}

export interface IPListItem {
  id: number
  ip: string
  type: number
  reason: string
  expire_time: string | null
  created_at: string
}

export interface ConfigItem {
  id: number
  config_key: string
  config_value: string
  config_desc: string
  created_at: string
  updated_at: string
}

export interface SiteItem {
  id: number
  name: string
  host: string
  upstream: string
  enabled: boolean
  pass_host: boolean
  tls_skip_verify: boolean
  created_at: string
  updated_at: string
}

export interface SiteHealth {
  site_id: number
  upstream: string
  healthy: boolean
  latency_ms: number
  status_code?: number
  error?: string
}

export interface UserItem {
  id: number
  username: string
  email: string
  status: number
  must_change_password: boolean
  last_login_at: string | null
  created_at: string
}

export interface IntegrationEndpoint {
  method: string
  path: string
  description: string
}

export interface IntegrationConfig {
  enabled: boolean
  key_configured: boolean
  key_masked: string
  header: string
  endpoints: IntegrationEndpoint[]
}

export interface PolicyRule {
  id: number
  name: string
  category: string
  target: 'all' | 'uri' | 'args' | 'headers' | 'body' | 'method'
  pattern: string
  action: 1 | 2
  enabled: boolean
  priority: number
  source: 'custom' | 'import' | 'auto'
  version: string
  description: string
  created_at: string
  updated_at: string
}

export interface PolicySettings {
  auto_update: boolean
  url: string
  interval_minutes: number
  public_key_configured: boolean
  last_version: string
  last_update: string
  last_error: string
  counts: Record<string, number>
}

export interface PolicyRecommendation {
  id: string
  title: string
  reason: string
  config_key?: string
  current?: number
  recommended?: number
  risk: 'low' | 'medium' | 'high'
}

export interface DeviceSettings {
  auto_block_enabled: boolean
  auto_block_severity: number
  auto_block_seconds: number
}

export interface DeviceEvent {
  id: number
  device_name: string
  vendor: string
  format: string
  source_ip: string
  event_type: string
  severity: number
  event_ip: string
  message: string
  action_taken: string
  created_at: string
}

export type ProtectionStatus = Record<string, number>

export interface ResourceAlert {
  resource: string
  level: 'warning' | 'critical'
  message: string
  current: number
  threshold: number
  unit: string
}

export interface AlertThresholds {
  cpu_percent: number
  memory_percent: number
  disk_percent: number
  log_size_mb: number
  request_rate: number
}

export interface SystemResources {
  hostname: string
  os: string
  platform: string
  uptime_seconds: number
  cpu_percent: number
  memory_used_bytes: number
  memory_total_bytes: number
  memory_percent: number
  disk_used_bytes: number
  disk_total_bytes: number
  disk_percent: number
  log_size_bytes: number
  request_rate: number
  thresholds: AlertThresholds
  alerts: ResourceAlert[]
}
