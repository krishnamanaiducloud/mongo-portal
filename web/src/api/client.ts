// Minimal fetch wrapper for the portal API. Credentials are cookies managed
// by the browser (HttpOnly); nothing sensitive is kept in JS storage. The
// CSRF token is held in memory only.

let csrfToken = '';

export function setCsrfToken(token: string | undefined) {
  if (token) csrfToken = token;
}

export const SESSION_LOST_EVENT = 'portal:session-lost';
export const SSO_LOST_EVENT = 'portal:sso-lost';

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;
  readonly mongoCode?: number;
  readonly codeName?: string;

  constructor(status: number, code: string, message: string, requestId?: string, mongoCode?: number, codeName?: string) {
    super(message);
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.mongoCode = mongoCode;
    this.codeName = codeName;
  }
}

export function isSessionError(e: unknown): boolean {
  return e instanceof ApiError && (e.code === 'mongo_session_required' || e.code === 'mongo_session_expired');
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return 'Unexpected error';
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

export async function api<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const method = opts.method ?? 'GET';
  const headers: Record<string, string> = { Accept: 'application/json', ...opts.headers };
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken;

  let res: Response;
  try {
    res = await fetch(`/api/v1${path}`, {
      method,
      headers,
      credentials: 'same-origin',
      redirect: 'manual',
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      signal: opts.signal,
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError(0, 'network_error', 'The portal could not be reached. Check your connection.');
  }

  // The OAuth proxy answers expired SSO sessions with a redirect to the
  // identity provider; surface that as an SSO error.
  const type = res.headers.get('Content-Type') ?? '';
  if (res.type === 'opaqueredirect' || (res.ok && !type.includes('application/json'))) {
    window.dispatchEvent(new CustomEvent(SSO_LOST_EVENT));
    throw new ApiError(401, 'sso_required', 'Your corporate SSO session has ended. Sign in again.');
  }

  let data: unknown;
  try {
    data = await res.json();
  } catch {
    data = {};
  }
  if (!res.ok) {
    const err = (data as { error?: { code?: string; message?: string; requestId?: string; mongoCode?: number; codeName?: string } }).error;
    const apiErr = new ApiError(res.status, err?.code ?? `http_${res.status}`, err?.message ?? res.statusText, err?.requestId, err?.mongoCode, err?.codeName);
    if (isSessionError(apiErr)) window.dispatchEvent(new CustomEvent(SESSION_LOST_EVENT, { detail: apiErr.code }));
    if (apiErr.code === 'sso_required') window.dispatchEvent(new CustomEvent(SSO_LOST_EVENT));
    throw apiErr;
  }
  return data as T;
}

export const enc = encodeURIComponent;

export function nsPath(db: string, coll?: string): string {
  return coll === undefined ? `/databases/${enc(db)}` : `/databases/${enc(db)}/collections/${enc(coll)}`;
}

/** POSTs a file body (import uploads and previews) with the CSRF token. */
export async function upload<T>(path: string, body: Blob, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api/v1${path}`, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': csrfToken },
      credentials: 'same-origin',
      redirect: 'manual',
      body,
      signal,
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError(0, 'network_error', 'The upload did not reach the portal. Check your connection.');
  }
  let data: unknown;
  try {
    data = await res.json();
  } catch {
    data = {};
  }
  if (!res.ok) {
    const err = (data as { error?: { code?: string; message?: string; requestId?: string } }).error;
    const apiErr = new ApiError(res.status, err?.code ?? `http_${res.status}`, err?.message ?? res.statusText, err?.requestId);
    if (isSessionError(apiErr)) window.dispatchEvent(new CustomEvent(SESSION_LOST_EVENT, { detail: apiErr.code }));
    throw apiErr;
  }
  return data as T;
}

/** Builds a query string, skipping empty values. */
export function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '' && v !== false) u.set(k, String(v));
  }
  const s = u.toString();
  return s ? `?${s}` : '';
}
