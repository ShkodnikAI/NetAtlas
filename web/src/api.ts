// Клиент API карты сети. Токен хранится только в памяти страницы:
// не в localStorage, не в cookies, не в URL.

export interface NodeInfo {
  id: string;
  kind: string;
  label: string;
  class?: string;
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

export interface ScanView {
  id: number;
  status: string;
  stages: string[];
  counts: { devices: number; hosts: number; links: number; snmp_targets: number; leases?: number; leases_skipped?: number };
  error?: string;
  subnets?: string[];
}

export interface Forecast {
  days_to_full?: number;
  confidence?: number;
  slope_per_day?: number;
  insufficient?: string;
}

export interface ComputerSummary {
  id: string;
  hostname: string;
  status: string;
  last_seen?: string;
  inventory_at?: string;
  findings?: Record<string, number>;
  max_priority?: number;
  worst_days_to_full?: number;
}

export interface Finding {
  rule_id: string;
  severity: string;
  fact: string;
  threshold?: string;
  source: string;
  advice: string;
  priority: number;
}

export interface ComputerCard {
  id: string;
  hostname: string;
  status: string;
  inventory_at?: string;
  inventory?: {
    os?: { caption?: string; version?: string; build_number?: string; architecture?: string; last_boot_up_time?: string; latest_hotfix?: string };
    hardware?: { total_physical_memory?: string; cpus?: { name?: string; cores?: number; logical?: number; max_clock_mhz?: number }[]; memory_modules?: { slot?: string; capacity?: string; speed_mhz?: number; manufacturer?: string }[]; base_board?: { manufacturer?: string; product?: string }; bios?: { manufacturer?: string; version?: string; release_date?: string } };
    disks?: { disks?: { friendly_name?: string; serial?: string; media_type?: string; size?: string; health?: string; wear?: number; temperature?: number }[]; volumes?: { drive_letter?: string; label?: string; file_system?: string; size?: string; size_remaining?: string }[] };
    network?: { name?: string; description?: string; mac?: string; link_speed?: string; status?: string; ipv4?: string[] }[];
    drivers?: { device_name?: string; manufacturer?: string; version?: string; date?: string }[];
    programs?: { name?: string; version?: string; publisher?: string; install_date?: string }[];
    collector_errors?: string[];
  };
  findings?: Finding[];
  forecasts?: Record<string, Forecast>;
}

export interface DiskView {
  agent_id: string;
  hostname: string;
  drive: string;
  label?: string;
  file_system?: string;
  capacity_bytes: number;
  used_bytes: number;
  free_pct: number;
  forecast: Forecast;
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

  config(): Promise<{ subnets: string[]; snmp: boolean; audit_ok: boolean }> {
    return this.req('GET', '/api/config');
  }

  devices(): Promise<{ devices: DeviceInfo[] }> {
    return this.req('GET', '/api/devices');
  }

  alerts(): Promise<{ alerts: { id: number; device_id: string; created: string; open: boolean }[] }> {
    return this.req('GET', '/api/alerts');
  }

  ackAlert(id: number): Promise<{ ok: boolean }> {
    return this.req('POST', `/api/alerts/${id}/ack`);
  }

  startScan(body: {
    subnets: string[]; ping: boolean; names: boolean; snmp_targets: string[]; confirm: boolean;
    leases_path?: string; leases_format?: string;
  }): Promise<{ id: number }> {
    return this.req('POST', '/api/scan', body);
  }

  scanState(id: number): Promise<ScanView> {
    return this.req('GET', `/api/scan/${id}`);
  }

  devicesList(): Promise<{ devices: DeviceInfo[] }> {
    return this.req('GET', '/api/devices');
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

  computers(): Promise<{ computers: ComputerSummary[] }> {
    return this.req('GET', '/api/computers');
  }

  computer(id: string): Promise<ComputerCard> {
    return this.req<ComputerCard>('GET', `/api/computers/${encodeURIComponent(id)}`);
  }

  disks(): Promise<{ disks: DiskView[] }> {
    return this.req('GET', '/api/disks');
  }

  qualityMatrix(): Promise<{ matrix: { agent_id: string; target: string; latest: Record<string, number>; worst: string }[] }> {
    return this.req('GET', '/api/quality/matrix');
  }

  qualityBottlenecks(): Promise<{ bottlenecks: { agent_id: string; hostname: string; finding: Finding }[] }> {
    return this.req('GET', '/api/quality/bottlenecks');
  }

  qualitySeries(kind: string): Promise<{ series: { window: string; avg: number; p95: number; max: number }[] }> {
    return this.req('GET', `/api/quality/series?agent=_&target=_&kind=${encodeURIComponent(kind)}&hourly=1&from=${encodeURIComponent(new Date(Date.now() - 24 * 3600e3).toISOString())}`);
  }
}
