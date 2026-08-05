import type { APIEnvelope } from '../types/api'

const API_PREFIX = '/api/v1'
let csrfToken = sessionStorage.getItem('jingshield_csrf') || ''

export class APIError extends Error {
  constructor(
    message: string,
    public readonly code: number,
    public readonly status: number,
  ) {
    super(message)
    this.name = 'APIError'
  }
}

export function setCSRFToken(token: string) {
  csrfToken = token
  if (token) sessionStorage.setItem('jingshield_csrf', token)
  else sessionStorage.removeItem('jingshield_csrf')
}

export function getCSRFToken() {
  return csrfToken
}

export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method || 'GET').toUpperCase()
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (!['GET', 'HEAD'].includes(method) && csrfToken) headers.set('X-CSRF-Token', csrfToken)

  let response: Response
  try {
    response = await fetch(`${API_PREFIX}${path}`, {
      ...init,
      headers,
      credentials: 'include',
    })
  } catch {
    throw new APIError('无法连接到鲸盾服务，请检查服务状态', -1, 0)
  }

  let envelope: APIEnvelope<T>
  try {
    envelope = (await response.json()) as APIEnvelope<T>
  } catch {
    throw new APIError('服务返回了无法识别的响应', -1, response.status)
  }
  if (!response.ok || envelope.code !== 0) {
    throw new APIError(envelope.message || '请求失败', envelope.code, response.status)
  }
  return envelope.data
}

export function jsonBody(value: unknown): RequestInit {
  return { body: JSON.stringify(value) }
}
