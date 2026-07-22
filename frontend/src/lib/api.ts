// Thin fetch wrapper: attaches the in-memory access token, sends the
// httpOnly refresh cookie automatically (credentials: 'include'), and on a
// 401 tries exactly one silent refresh before giving up. The access token
// itself is never persisted here — AuthContext owns where it lives.

const API_BASE = import.meta.env.VITE_API_BASE_URL

type TokenGetter = () => string | null
type TokenSetter = (token: string | null) => void

let getAccessToken: TokenGetter = () => null
let setAccessToken: TokenSetter = () => {}
let onAuthFailure: () => void = () => {}

export function configureApi(opts: {
  getToken: TokenGetter
  setToken: TokenSetter
  onAuthFailure: () => void
}) {
  getAccessToken = opts.getToken
  setAccessToken = opts.setToken
  onAuthFailure = opts.onAuthFailure
}

async function refreshAccessToken(): Promise<string | null> {
  const res = await fetch(`${API_BASE}/auth/refresh`, {
    method: 'POST',
    credentials: 'include',
  })
  if (!res.ok) return null
  const data = await res.json()
  setAccessToken(data.access_token)
  return data.access_token as string
}

export async function apiFetch(
  path: string,
  init: RequestInit = {},
  retryOn401 = true,
): Promise<Response> {
  const token = getAccessToken()
  const headers = new Headers(init.headers)
  if (token) headers.set('Authorization', `Bearer ${token}`)
  if (!headers.has('Content-Type') && init.body) headers.set('Content-Type', 'application/json')

  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    credentials: 'include',
  })

  if (res.status === 401 && retryOn401) {
    const newToken = await refreshAccessToken()
    if (newToken) return apiFetch(path, init, false)
    onAuthFailure()
  }

  return res
}

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

export async function apiJSON<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await apiFetch(path, init)
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }))
    throw new ApiError(body.error ?? `Request failed: ${res.status}`, res.status)
  }
  if (res.status === 204) return undefined as T
  return res.json()
}
