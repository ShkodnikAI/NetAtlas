// Тесты логики мастера сканирования и таблицы устройств (NR-005):
// без сети, DOM через jsdom.

import { describe, expect, it } from 'vitest';
import type { DeviceInfo } from './api';
import {
  deviceRow,
  displayName,
  expectedStages,
  renderAlerts,
  renderDevicesTable,
  renderProgress,
  setupScanScreen,
  sortDevicesByIP,
  startScan,
  subnetGateway,
  type ScreenElems,
} from './scan';

function elems(): ScreenElems {
  const mk = (tag: string): any => document.createElement(tag);
  return {
    subnets: mk('div'),
    ping: mk('input'),
    names: mk('input'),
    snmp: mk('input'),
    snmpNote: mk('p'),
    leasesPath: mk('input'),
    leasesFormat: mk('select'),
    run: mk('button'),
    error: mk('span'),
    progressWrap: mk('div'),
    progress: mk('div'),
    status: mk('p'),
    alertsList: mk('div'),
    tableBody: mk('tbody'),
    badge: mk('span'),
  };
}

describe('setupScanScreen', () => {
  it('рисует чекбоксы подсетей и блокирует SNMP без учётных данных', () => {
    const el = elems();
    setupScanScreen({ subnets: ['10.0.0.0/24', '192.168.1.0/24'], snmp: false }, el);
    const boxes = el.subnets.querySelectorAll('input[type="checkbox"]');
    expect(boxes).toHaveLength(2);
    expect((boxes[0] as HTMLInputElement).value).toBe('10.0.0.0/24');
    expect((boxes[0] as HTMLInputElement).checked).toBe(true);
    expect(el.snmp.disabled).toBe(true);
    expect(el.snmpNote.hidden).toBe(false);
  });

  it('все подсети отмечены по умолчанию, подсказка SNMP из первой подсети (NR-031 п.7)', () => {
    const el = elems();
    setupScanScreen({ subnets: ['192.168.100.0/24'], snmp: true }, el);
    const boxes = [...el.subnets.querySelectorAll('input[type="checkbox"]')];
    expect(boxes.every((b) => (b as HTMLInputElement).checked)).toBe(true);
    expect(el.snmp.placeholder).toBe('192.168.100.1');
  });

  it('мусор вместо подсети не ломает подсказку', () => {
    const el = elems();
    setupScanScreen({ subnets: ['мусор'], snmp: true }, el);
    expect(el.snmp.placeholder).toBe('');
  });
});

describe('startScan', () => {
  it('собирает выбранные подсети и всегда ставит confirm=true', () => {
    const el = elems();
    setupScanScreen({ subnets: ['10.0.0.0/24', '192.168.1.0/24'], snmp: true }, el);
    (el.subnets.querySelectorAll('input[type="checkbox"]')[1] as HTMLInputElement).checked = false;
    el.ping.checked = true;
    el.names.checked = false;
    el.snmp.value = '192.168.1.1';
    const body = startScan(el);
    expect(body.subnets).toEqual(['10.0.0.0/24']);
    expect(body.confirm).toBe(true);
    expect(body.ping).toBe(true);
    expect(body.names).toBe(false);
    expect(body.snmp_targets).toEqual(['192.168.1.1']);
  });

  it('пустой выбор SNMP даёт пустой список целей', () => {
    const el = elems();
    setupScanScreen({ subnets: ['10.0.0.0/24'], snmp: true }, el);
    el.snmp.value = ' , ';
    expect(startScan(el).snmp_targets).toEqual([]);
  });

  it('без пути аренд поля leases в тело не попадают (NR-023)', () => {
    const el = elems();
    setupScanScreen({ subnets: ['10.0.0.0/24'], snmp: true }, el);
    el.leasesFormat.value = 'csv';
    const body = startScan(el);
    expect(body.leases_path).toBeUndefined();
    expect(body.leases_format).toBeUndefined();
  });

  it('путь аренд уходит вместе с форматом (NR-023)', () => {
    const el = elems();
    setupScanScreen({ subnets: ['10.0.0.0/24'], snmp: true }, el);
    el.leasesFormat.append(new Option('isc (dhcpd.leases)', 'isc'));
    el.leasesPath.value = ' /var/lib/dhcp/dhcpd.leases ';
    el.leasesFormat.value = 'isc';
    const body = startScan(el);
    expect(body.leases_path).toBe('/var/lib/dhcp/dhcpd.leases');
    expect(body.leases_format).toBe('isc');
  });
});

describe('expectedStages', () => {
  it('считает стадии по методам', () => {
    expect(expectedStages(false, false, false)).toBe(1);
    expect(expectedStages(true, true, false)).toBe(3);
    expect(expectedStages(true, true, true)).toBe(5);
  });

  it('аренды добавляют стадию (NR-023)', () => {
    expect(expectedStages(false, false, false, true)).toBe(2);
    expect(expectedStages(true, true, true, true)).toBe(6);
  });
});

describe('renderProgress', () => {
  it('running показывает долю стадий', () => {
    const el = elems();
    renderProgress(el, { id: 1, status: 'running', stages: ['arp'], counts: { devices: 0, hosts: 0, links: 0, snmp_targets: 0 } }, 3);
    expect(el.progressWrap.hidden).toBe(false);
    expect(el.progress.style.width).toBe('33%');
    expect(el.status.textContent).toContain('Идёт сканирование');
  });

  it('done показывает итог', () => {
    const el = elems();
    renderProgress(el, {
      id: 1, status: 'done', stages: ['arp', 'ping', 'snmp', 'topology'],
      counts: { devices: 7, hosts: 2, links: 5, snmp_targets: 1 },
    }, 4);
    expect(el.progress.style.width).toBe('100%');
    expect(el.status.textContent).toContain('Готово: устройств 7');
  });

  it('failed показывает ошибку', () => {
    const el = elems();
    renderProgress(el, { id: 1, status: 'failed', stages: [], counts: { devices: 0, hosts: 0, links: 0, snmp_targets: 0 }, error: 'таймаут' }, 3);
    expect(el.status.textContent).toContain('таймаут');
  });
});

describe('deviceRow', () => {
  const base: DeviceInfo = {
    id: '00:00:00:00:00:0b',
    hostname: 'printer',
    class: 'unknown',
    ips: ['10.0.0.11'],
    names: [],
    observations: [
      { source: 'arp', seen: '2026-10-26T08:00:00Z' },
      { source: 'ping', seen: '2026-10-26T09:00:00Z' },
    ],
    vendor: 'Cisco',
    ssid: '',
    manual: false,
    verified: false,
  };

  it('значок роли 20 px рядом с именем, имя — текстом: HTML в имени безопасен (NR-036 п.1)', () => {
    const tr = deviceRow(base, () => {});
    // Значок строится из статической таблицы типов (kind нет —
    // unknown), данные API в атрибуты не попадают.
    const icon = tr.querySelector('img.dev-icon');
    expect(icon).not.toBeNull();
    expect(icon?.getAttribute('width')).toBe('20');
    expect(icon?.getAttribute('src')).toContain('data:image/svg+xml');
    expect(tr.innerHTML).not.toContain('<img src=x');
    expect(tr.innerHTML).not.toContain('onerror');
    expect(tr.textContent).toContain('printer');
  });

  it('семь ячеек: имя, IP, MAC, производитель, класс, время, источники (NR-031)', () => {
    const tr = deviceRow(base, () => {});
    const tds = [...tr.querySelectorAll('td')];
    expect(tds).toHaveLength(7);
    expect(tds[0]?.textContent).toBe('printer');
    expect(tds[1]?.textContent).toBe('10.0.0.11');
    expect(tds[2]?.textContent).toBe('00:00:00:00:00:0b');
    expect(tds[3]?.textContent).toBe('Cisco');
    expect(tds[5]?.textContent).not.toBe('—');
    expect(tds[6]?.textContent).toBe('arp, ping');
  });

  it('класс — выбор из четырёх вариантов, смена вызывает обработчик (NR-031)', () => {
    let got: [string, string] | null = null;
    const tr = deviceRow(base, (id, klass) => {
      got = [id, klass];
    });
    const select = tr.querySelector('select') as HTMLSelectElement;
    expect(select.options).toHaveLength(4);
    expect(select.value).toBe('unknown');
    select.value = 'guest';
    select.dispatchEvent(new Event('change'));
    expect(got).toEqual(['00:00:00:00:00:0b', 'guest']);
  });

  it('имя без hostname берётся из первого имени, потом производитель', () => {
    const named: DeviceInfo = {
      ...base,
      hostname: '',
      names: [{ source: 'dns', name: 'nas.local', seen: '2026-10-26T08:00:00Z' }],
    };
    expect(displayName(named)).toBe('nas.local');
    const vendored: DeviceInfo = { ...base, hostname: '', names: [] };
    expect(displayName(vendored)).toBe('Cisco');
    expect(displayName({ ...base, hostname: '', names: [], vendor: '' })).toBe(base.id);
  });

  it('без наблюдений время — прочерк, источники пусты', () => {
    const tr = deviceRow({ ...base, observations: [] }, () => {});
    const tds = [...tr.querySelectorAll('td')];
    expect(tds[5]?.textContent).toBe('—');
    expect(tds[6]?.textContent).toBe('');
  });
});

describe('subnetGateway', () => {
  it('первый хост подсети (NR-031 п.7)', () => {
    expect(subnetGateway('192.168.100.0/24')).toBe('192.168.100.1');
    expect(subnetGateway('10.0.0.128/25')).toBe('10.0.0.1');
  });

  it('не IPv4 или мусор — null', () => {
    expect(subnetGateway('fd00::/64')).toBeNull();
    expect(subnetGateway('мусор')).toBeNull();
    expect(subnetGateway('300.1.1.0/24')).toBeNull();
    expect(subnetGateway('10.0.0.0')).toBeNull();
  });
});

describe('sortDevicesByIP (NR-031 п.3)', () => {
  const dev = (id: string, ips: string[]): DeviceInfo => ({
    id,
    hostname: '',
    class: 'unknown',
    ips,
    names: [],
    observations: [],
    vendor: '',
    ssid: '',
    manual: false,
    verified: false,
  });

  it('сортирует по первому IPv4 численно, без адреса — в конец', () => {
    const sorted = sortDevicesByIP([
      dev('aa', ['192.168.100.23']),
      dev('bb', []),
      dev('cc', ['10.0.0.2', '192.168.100.1']),
      dev('dd', ['192.168.100.9']),
    ]);
    expect(sorted.map((d) => d.id)).toEqual(['cc', 'dd', 'aa', 'bb']);
  });

  it('два без адреса сортируются по MAC', () => {
    const sorted = sortDevicesByIP([dev('ff', []), dev('aa', [])]);
    expect(sorted.map((d) => d.id)).toEqual(['aa', 'ff']);
  });
});

describe('renderDevicesTable (NR-031 п.3)', () => {
  const tbody = (): HTMLElement => document.createElement('tbody');
  const dev = (id: string, ips: string[]): DeviceInfo => ({
    id,
    hostname: '',
    class: 'unknown',
    ips,
    names: [],
    observations: [],
    vendor: '',
    ssid: '',
    manual: false,
    verified: false,
  });

  it('пустой список — одна строка с подсказкой запустить скан', () => {
    const tb = tbody();
    renderDevicesTable(tb, [], () => {});
    const rows = tb.querySelectorAll('tr');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.textContent).toContain('Устройств пока нет');
    expect(rows[0]?.textContent).toContain('запустите сканирование');
  });

  it('строки идут по возрастанию IP', () => {
    const tb = tbody();
    renderDevicesTable(tb, [dev('bb', ['192.168.100.20']), dev('aa', ['192.168.100.3'])], () => {});
    const tds = [...tb.querySelectorAll('tr td:first-child')];
    // Имя без hostname/имени — MAC; порядок: 192.168.100.3, потом .20.
    expect(tds.map((td) => td.textContent)).toEqual(['aa', 'bb']);
  });
});

describe('renderAlerts', () => {
  it('бейдж скрыт без оповещений и показывает число с ними', () => {
    const el = elems();
    renderAlerts(el, [], () => {});
    expect(el.badge.hidden).toBe(true);

    let acked = 0;
    renderAlerts(el, [{ id: 3, device_id: '00:00:00:00:00:0d', created: '2026-10-23T00:00:00Z', open: true }], () => {
      acked++;
    });
    expect(el.badge.hidden).toBe(false);
    expect(el.badge.textContent).toBe('1');
    expect(el.alertsList.textContent).toContain('00:00:00:00:00:0d');
    (el.alertsList.querySelector('button') as HTMLButtonElement).click();
    expect(acked).toBe(1);
  });
});
