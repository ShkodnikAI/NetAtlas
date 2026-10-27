// Экраны «Мастер сканирования» и «Найденные устройства» (NR-005):
// запуск сканирования по явному подтверждению, прогресс по стадиям,
// классификация найденного, оповещения о новых неизвестных.
// NR-031: подсети с подсказкой из конфигурации сервера, таблица
// устройств с временем и источниками, сортировка по IP.

import type { DeviceInfo, ScanView } from './api';
import type { storeAlert } from './types';
import { svgIcon } from './nodes';

const CLASS_OPTIONS: [string, string][] = [
  ['managed', 'Моё'],
  ['guest', 'Гость'],
  ['known_no_agent', 'Без агента'],
  ['unknown', 'Неизвестное'],
];

export interface ScreenElems {
  subnets: HTMLElement;
  ping: HTMLInputElement;
  names: HTMLInputElement;
  snmp: HTMLInputElement;
  snmpNote: HTMLElement;
  leasesPath: HTMLInputElement;
  leasesFormat: HTMLSelectElement;
  run: HTMLButtonElement;
  error: HTMLElement;
  progressWrap: HTMLElement;
  progress: HTMLElement;
  status: HTMLElement;
  alertsList: HTMLElement;
  tableBody: HTMLElement;
  badge: HTMLElement;
}

// subnetGateway — первый хост подсети («192.168.100.0/24» →
// «192.168.100.1»): нейтральная подсказка для целей SNMP вместо
// чужих примеров. Не IPv4 или мусор — null.
export function subnetGateway(cidr: string): string | null {
  const [base, prefix] = cidr.split('/');
  const octets = (base ?? '').split('.');
  if (octets.length !== 4 || prefix === undefined || prefix === '') return null;
  const nums: number[] = [];
  for (const o of octets) {
    const n = Number(o);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    nums.push(n);
  }
  return `${nums[0]}.${nums[1]}.${nums[2]}.1`;
}

// setupScanScreen — заполняет список подсетей из /api/config:
// все подсети сервера отмечены по умолчанию (NR-031 п.7), подсказка
// SNMP берётся из первой подсети.
export async function setupScanScreen(
  cfg: { subnets: string[]; snmp: boolean },
  el: ScreenElems,
): Promise<void> {
  el.subnets.textContent = '';
  for (const cidr of cfg.subnets) {
    const label = document.createElement('label');
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.value = cidr;
    box.checked = true;
    label.append(box, document.createTextNode(` ${cidr}`));
    el.subnets.append(label);
  }
  if (cfg.subnets.length > 0) {
    const gw = subnetGateway(cfg.subnets[0] ?? '');
    if (gw !== null) el.snmp.placeholder = gw;
  }
  if (!cfg.snmp) {
    el.snmp.disabled = true;
    el.snmp.value = '';
    el.snmpNote.hidden = false;
  }
}

// startScan — явный запуск: confirm=true обязателен. Аренды (NR-023):
// оба поля уходят на сервер только вместе, при пустом пути формат
// игнорируется.
export function startScan(el: ScreenElems): {
  subnets: string[]; ping: boolean; names: boolean; snmp_targets: string[]; confirm: boolean;
  leases_path?: string; leases_format?: string;
} {
  const subnets = [...el.subnets.querySelectorAll('input[type="checkbox"]:checked')].map(
    (b) => (b as HTMLInputElement).value,
  );
  const snmpTargets = el.snmp.value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '');
  const out: {
    subnets: string[]; ping: boolean; names: boolean; snmp_targets: string[]; confirm: boolean;
    leases_path?: string; leases_format?: string;
  } = {
    subnets,
    ping: el.ping.checked,
    names: el.names.checked,
    snmp_targets: snmpTargets,
    confirm: true,
  };
  const path = el.leasesPath.value.trim();
  if (path !== '') {
    out.leases_path = path;
    out.leases_format = el.leasesFormat.value;
  }
  return out;
}

// expectedStages — сколько стадий ждать при выбранных методах.
export function expectedStages(ping: boolean, names: boolean, snmp: boolean, leases = false): number {
  let n = 1; // arp
  if (ping) n++;
  if (names) n++;
  if (leases) n++; // leases
  if (snmp) n += 2; // snmp + topology
  return n;
}

// renderProgress — полоса прогресса и статус по состоянию скана.
export function renderProgress(el: ScreenElems, view: ScanView, expected: number): void {
  el.progressWrap.hidden = false;
  const done = view.stages.length;
  if (view.status === 'done') {
    el.progress.style.width = '100%';
    el.status.textContent =
      `Готово: устройств ${view.counts.devices}, хостов ${view.counts.hosts}, ` +
      `связей ${view.counts.links}, SNMP-целей ${view.counts.snmp_targets}.`;
  } else if (view.status === 'failed') {
    el.progress.style.width = '0';
    el.status.textContent = `Ошибка: ${view.error ?? 'неизвестная'}`;
  } else {
    el.progress.style.width = `${Math.min(100, Math.round((done / Math.max(1, expected)) * 100))}%`;
    el.status.textContent = `Идёт сканирование: стадия ${done + 1} из ${expected}`;
  }
}

// ipSortKey — числовой ключ первого IPv4-адреса (чем меньше адрес,
// тем выше строка); без адреса или не IPv4 — в конец списка.
export function ipSortKey(info: DeviceInfo): number {
  const first = info.ips[0];
  if (first === undefined) return Number.POSITIVE_INFINITY;
  const octets = first.split('.');
  if (octets.length !== 4) return Number.POSITIVE_INFINITY;
  let key = 0;
  for (const o of octets) {
    const n = Number(o);
    if (!Number.isInteger(n) || n < 0 || n > 255) return Number.POSITIVE_INFINITY;
    key = key * 256 + n;
  }
  return key;
}

// displayName — имя или производитель (NR-031 п.3): hostname, первое
// имя, производитель, идентификатор (MAC).
export function displayName(info: DeviceInfo): string {
  if (info.hostname !== '') return info.hostname;
  const first = info.names[0];
  if (first !== undefined && first.name !== '') return first.name;
  if (info.vendor !== '') return info.vendor;
  return info.id;
}

// lastSeenOf — время последнего обнаружения: максимум по наблюдениям.
export function lastSeenOf(info: DeviceInfo): Date | null {
  let latest: Date | null = null;
  for (const o of info.observations) {
    const t = new Date(o.seen);
    if (Number.isNaN(t.getTime())) continue;
    if (latest === null || t.getTime() > latest.getTime()) latest = t;
  }
  return latest;
}

// sourcesOf — уникальные источники наблюдений по алфавиту.
export function sourcesOf(info: DeviceInfo): string {
  const set = new Set<string>();
  for (const o of info.observations) set.add(o.source);
  return [...set].sort().join(', ');
}

// sortDevicesByIP — сортировка по IP по умолчанию (NR-031 п.3),
// устройства без адреса — в конец, между собой по MAC.
export function sortDevicesByIP(devices: DeviceInfo[]): DeviceInfo[] {
  return [...devices].sort((a, b) => {
    const ka = ipSortKey(a);
    const kb = ipSortKey(b);
    if (ka !== kb) return ka < kb ? -1 : 1;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
}

// deviceRow — строка таблицы найденных устройств: значок роли и
// имя/производитель, IP, MAC, класс с выбором, время последнего
// обнаружения и источники (NR-031 п.3, NR-036 п.1 — значок 20 px
// рядом с именем).
export function deviceRow(
  info: DeviceInfo,
  onClass: (id: string, klass: string) => void,
): HTMLTableRowElement {
  const tr = document.createElement('tr');
  // Имя: значок роли из статической таблицы типов (не данные API) и
  // имя текстом (textContent) — HTML в имени не исполняется.
  const nameCell = document.createElement('td');
  const icon = document.createElement('img');
  icon.src = svgIcon(info.kind ?? 'unknown');
  icon.alt = '';
  icon.width = 20;
  icon.height = 20;
  icon.className = 'dev-icon';
  nameCell.append(icon, document.createTextNode(displayName(info)));
  const cell = (value: string): HTMLTableCellElement => {
    const td = document.createElement('td');
    td.textContent = value;
    return td;
  };
  tr.append(
    nameCell,
    cell(info.ips.join(', ')),
    cell(info.id),
    cell(info.vendor),
  );
  const classCell = document.createElement('td');
  const select = document.createElement('select');
  select.setAttribute('aria-label', `Класс устройства ${info.id}`);
  for (const [value, label] of CLASS_OPTIONS) {
    const opt = new Option(label, value);
    if (info.class === value) opt.selected = true;
    select.append(opt);
  }
  select.addEventListener('change', () => onClass(info.id, select.value));
  classCell.append(select);
  tr.append(classCell);

  const seen = lastSeenOf(info);
  tr.append(cell(seen === null ? '—' : seen.toLocaleString()));
  tr.append(cell(sourcesOf(info)));
  return tr;
}

// renderDevicesTable — таблица устройств: сортировка по IP и явное
// пустое состояние (NR-031 п.3).
export function renderDevicesTable(
  tbody: HTMLElement,
  devices: DeviceInfo[],
  onClass: (id: string, klass: string) => void,
): void {
  tbody.textContent = '';
  if (devices.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.className = 'empty';
    td.colSpan = 7;
    td.textContent = 'Устройств пока нет — запустите сканирование.';
    tr.append(td);
    tbody.append(tr);
    return;
  }
  for (const d of sortDevicesByIP(devices)) {
    tbody.append(deviceRow(d, onClass));
  }
}

// renderAlerts — список открытых оповещений с разбором.
export function renderAlerts(
  el: ScreenElems,
  alerts: storeAlert[],
  onAck: (id: number) => void,
): void {
  el.alertsList.textContent = '';
  el.badge.hidden = alerts.length === 0;
  el.badge.textContent = String(alerts.length);
  for (const a of alerts) {
    const item = document.createElement('div');
    item.className = 'alert-item';
    const text = document.createElement('span');
    text.textContent = `Новое неизвестное устройство: ${a.device_id}`;
    const ack = document.createElement('button');
    ack.textContent = 'Разобрать';
    ack.addEventListener('click', () => onAck(a.id));
    item.append(text, ack);
    el.alertsList.append(item);
  }
}
