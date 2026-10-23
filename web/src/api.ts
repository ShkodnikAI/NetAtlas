// Клиент API карты сети. Токен хранится только в памяти страницы:
// не в localStorage, не в cookies, не в URL.

export interface NodeInfo {
  id: string;
  kind: string;
  label: string;
  manual: boolean;
  verified: boolean;
}

export interface LinkInfo {
  a: string;
  aPort: string;
  b: string;
  bPort: string;
  source: string;
  manual: boolean;
  verified: boolean;
}

export interface Graph {
  nodes: NodeInfo[];
  links: LinkInfo[];
}

export interface DeviceInfo {
  id: string;
  hostname: string;
  class: string;
  ips: string[];
  names: { source: string; name: string; seen: string }[];
  observations: { source: string; seen: string }[];
  vendor: string;
  ssid: string;
  manual: boolean;
  verified: boolean;
}

export interface VerifyReport {
  id: string;
  verified: boolean;
  results: { ip: string; alive: boolean; rtt_ms?: number }[];
}

export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

// humanize — понятный текст для кодов ответа; тело сервера
// используется, только если это простое сообщение об ошибке.
export function humanize(status: number, body: string): string {
  const text = parseErrorBody(body);
  if (text !== '') return text;
  switch (status) {
    case 400: return 'Сервер не принял запрос (400).';
    case 401: return 'Требуется токен доступа (401).';
    case 404: return 'Элемент не найден (404).';
    case 409: return 'Действие запрещено: элемент не ручной (409).';
    case 500: return 'Внутренняя ошибка сервера (500).';
    case 503: return 'Проверка недоступна на сервере (503).';
    default: return `Ошибка сервера (${status}).`;
  }
}

function parseErrorBody(body: string): string {
  try {
    const data = JSON.parse(body) as { error?: unknown };
    if (typeof data.error === 'string' && data.error !== '') return data.error;
  } catch {
    // тело не JSON — не ошибка клиента
  }
  return '';
}

export class NetatlasApi {
  private token = '';
  // Вызывается при 401: интерфейс снова запрашивает токен.
  onUnauthorized: (() => void) | null = null;

  setToken(token: string): void {
    this.token = token;
  }

  hasToken(): boolean {
    return this.token.length > 0;
  }

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const init: RequestInit = { method, headers: {} };
    if (this.token !== '') {
      init.headers = { Authorization: `Bearer ${this.token}` };
    }
    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }
    const res = await fetch(path, init);
    if (res.status === 401) {
      this.token = '';
      this.onUnauthorized?.();
      throw new ApiError(401, humanize(401, ''));
    }
    if (!res.ok) {
      throw new ApiError(res.status, humanize(res.status, await res.text()));
    }
    return (await res.json()) as T;
  }

  topology(): Promise<Graph> {
    return this.req<Graph>('GET', '/api/topology');
  }

  device(id: string): Promise<DeviceInfo> {
    return this.req<DeviceInfo>('GET', `/api/devices/${encodeURIComponent(id)}`);
  }

  addDevice(kind: string, name: string): Promise<{ id: string }> {
    return this.req('POST', '/api/devices', { kind, name });
  }

  updateDevice(
    id: string,
    patch: { name?: string; class?: string; verified?: boolean },
  ): Promise<DeviceInfo> {
    return this.req('PATCH', `/api/devices/${encodeURIComponent(id)}`, patch);
  }

  deleteDevice(id: string): Promise<{ ok: boolean }> {
    return this.req('DELETE', `/api/devices/${encodeURIComponent(id)}`);
  }

  addLink(a: string, aPort: string, b: string, bPort: string): Promise<{ id: string }> {
    return this.req('POST', '/api/links', { a, a_port: aPort, b, b_port: bPort });
  }

  deleteLink(id: string): Promise<{ ok: boolean }> {
    return this.req('DELETE', `/api/links/${encodeURIComponent(id)}`);
  }

  verify(id: string): Promise<VerifyReport> {
    return this.req('POST', `/api/devices/${encodeURIComponent(id)}/verify`);
  }
}
