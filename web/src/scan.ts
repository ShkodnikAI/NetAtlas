// Экраны «Мастер сканирования» и «Найденные устройства» (NR-005):
// запуск сканирования по явному подтверждению, прогресс по стадиям,
// классификация найденного, оповещения о новых неизвестных.

import type { DeviceInfo, ScanView } from './api';
import type { storeAlert } from './types';

const CLASS_BUTTONS: [string, string][] = [
  ['managed', 'Моё'],
  ['guest', 'Гость'],
  ['known_no_agent', 'Без агента'],
  ['unknown', 'Неизвестное'],
];

const CLASS_NAMES: Record<string, string> = {
  managed: 'управляемое (с агентом)',
  guest: 'гость',
  known_no_agent: 'известное без агента',
  unknown: 'неизвестное',
};

export interface ScreenElems {
  subnets: HTMLElement;
  ping: HTMLInputElement;
  names: HTMLInputElement;
  snmp: HTMLInputElement;
  snmpNote: HTMLElement;
  run: HTMLButtonElement;
  error: HTMLElement;
  progressWrap: HTMLElement;
  progress: HTMLElement;
  status: HTMLElement;
  alertsList: HTMLElement;
  tableBody: HTMLElement;
  badge: HTMLElement;
}

// setupScanScreen — заполняет список подсетей из /api/config.
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
  if (!cfg.snmp) {
    el.snmp.disabled = true;
    el.snmp.value = '';
    el.snmpNote.hidden = false;
  }
}

// startScan — явный запуск: confirm=true обязателен.
export function startScan(el: ScreenElems): { subnets: string[]; ping: boolean; names: boolean; snmp_targets: string[]; confirm: boolean } {
  const subnets = [...el.subnets.querySelectorAll('input[type="checkbox"]:checked')].map(
    (b) => (b as HTMLInputElement).value,
  );
  const snmpTargets = el.snmp.value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '');
  return {
    subnets,
    ping: el.ping.checked,
    names: el.names.checked,
    snmp_targets: snmpTargets,
    confirm: true,
  };
}

// expectedStages — сколько стадий ждать при выбранных методах.
export function expectedStages(ping: boolean, names: boolean, snmp: boolean): number {
  let n = 1; // arp
  if (ping) n++;
  if (names) n++;
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

// deviceRow — строка таблицы найденных устройств: имя, IP, MAC,
// производитель и выбор класса.
export function deviceRow(
  info: DeviceInfo,
  onClass: (id: string, klass: string) => void,
): HTMLTableRowElement {
  const tr = document.createElement('tr');
  const cell = (value: string): HTMLTableCellElement => {
    const td = document.createElement('td');
    td.textContent = value;
    return td;
  };
  const name = info.hostname !== '' ? info.hostname : info.id;
  tr.append(
    cell(name),
    cell(info.ips.join(', ')),
    cell(info.id),
    cell(info.vendor),
  );
  const actions = document.createElement('td');
  for (const [value, label] of CLASS_BUTTONS) {
    const b = document.createElement('button');
    b.textContent = label;
    if (info.class === value) b.setAttribute('aria-pressed', 'true');
    b.addEventListener('click', () => onClass(info.id, value));
    actions.append(b);
  }
  const cur = document.createElement('span');
  cur.className = 'badge';
  cur.textContent = CLASS_NAMES[info.class] ?? info.class;
  actions.append(document.createTextNode(' '), cur);
  tr.append(actions);
  return tr;
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
