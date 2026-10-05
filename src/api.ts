export type Priority = 'High' | 'Normal' | 'Low';

export interface Domain {
  id: number;
  domain: string;
  priority: Priority;
  is_alive: 0 | 1 | null;
  http_status: number | null;
  last_error: string | null;
  ssl_issuer: string | null;
  ssl_valid_to: string | null;
  ssl_error: string | null;
  ssl_checked_at: string | null;
  registered_domain: string | null;
  domain_valid_to: string | null;
  domain_error: string | null;
}

export interface Status {
  lastSslCheck: string | null;
  dispatch: { ok: boolean; error?: string; at: string } | null;
}

export class ApiError extends Error {}

async function request<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method: init.method ?? 'GET',
    headers: { 'Content-Type': 'application/json' },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
    credentials: 'same-origin',
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) throw new ApiError('หมดเวลาเข้าสู่ระบบ — กรุณารีเฟรชหน้านี้เพื่อล็อกอินใหม่');
  if (!res.ok) throw new ApiError(data.error || `เกิดข้อผิดพลาด (${res.status})`);
  return data as T;
}

export const api = {
  me: () => request<{ email: string }>('/me'),
  status: () => request<Status>('/status'),
  list: () => request<Domain[]>('/domains'),
  add: (domain: string, priority: Priority) => request<Domain>('/domains', { method: 'POST', body: { domain, priority } }),
  refresh: (id: number) => request<Domain>(`/domains/${id}/refresh`, { method: 'POST', body: {} }),
  remove: (id: number) => request<{ ok: true }>(`/domains/${id}`, { method: 'DELETE' }),
};
