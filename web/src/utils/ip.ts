/** Validate a literal IPv4/IPv6 address without DNS, zones or URL syntax. */
export function isIPAddress(value: string): boolean {
  if (!value || value !== value.trim() || /[\s/%\[\]]/.test(value)) return false
  if (!value.includes(':')) return value.split('.').length === 4 && value.split('.').every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)
  if (!/^[\da-f:.]+$/i.test(value)) return false
  try { return new URL(`http://[${value}]/`).hostname.startsWith('[') } catch { return false }
}

/** Canonicalize validated IPs for preview deduplication; leave raw entries in submissions. */
export function canonicalIPAddress(value: string): string {
  return value.includes(':') && isIPAddress(value) ? new URL(`http://[${value}]/`).hostname.slice(1, -1) : value
}

/** Block lists accept unicast literals only; unspecified and multicast targets are rejected. */
export function isBlockableIPAddress(value: string): boolean {
  if (!isIPAddress(value)) return false
  const canonical = canonicalIPAddress(value)
  if (canonical.includes(':')) {
    if (canonical === '::' || canonical.startsWith('ff')) return false
    if (canonical.startsWith('::ffff:')) {
      const tail = canonical.slice(7).split(':')
      const high = parseInt(tail[0], 16), low = parseInt(tail[1], 16)
      return !(high === 0 && low === 0) && !(high >>> 8 >= 224 && high >>> 8 <= 239)
    }
    return true
  }
  const octet = Number(canonical.split('.')[0])
  return canonical !== '0.0.0.0' && !(octet >= 224 && octet <= 239)
}

/** Validate exact, boundary-delimited prefix or CIDR filters; returns a user-facing error. */
export function validateIPFilter(value: string, mode: string): string {
  if (!value) return ''
  if (mode === 'exact') return isIPAddress(value) ? '' : '请输入完整的 IPv4 或 IPv6 地址'
  if (mode === 'cidr') {
    const parts = value.split('/')
    if (parts.length === 2 && isIPAddress(parts[0]) && /^\d{1,3}$/.test(parts[1]) && Number(parts[1]) <= (parts[0].includes(':') ? 128 : 32)) return ''
    return '请输入有效网段，例如 192.168.1.0/24 或 2001:db8::/32'
  }
  if (value.endsWith('.') && value.split('.').length <= 4 && value.slice(0, -1).split('.').every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)) return ''
  if (value.endsWith(':') && /^[\da-f:]+$/i.test(value) && isIPAddress(`${value}${value.endsWith('::') ? '' : ':'}1`)) return ''
  return '前缀须以点或冒号结束，例如 192.168. 或 2001:db8:；IPv6 推荐使用 CIDR 网段'
}

/** Split pasted literal IP entries; preserve duplicates for the 500-entry request limit. */
export function splitIPEntries(value: string): string[] {
  return value.trim().split(/[\s,，;；]+/).filter(Boolean)
}
