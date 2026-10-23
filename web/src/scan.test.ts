// Тесты логики мастера сканирования и таблицы устройств (NR-005):
// без сети, DOM через jsdom.

import { describe, expect, it } from 'vitest';
import type { DeviceInfo } from './api';
import {
  deviceRow,
  expectedStages,
  renderAlerts,
  renderProgress,
  setupScanScreen,
  startScan,
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
    observations: [],
    vendor: 'Cisco',
    ssid: '',
    manual: false,
    verified: false,
  };

  it('значения вставляются текстом: HTML в имени безопасен', () => {
    const tr = deviceRow(base, () => {});
    expect(tr.innerHTML).not.toContain('<img');
    expect(tr.textContent).toContain('printer');
  });

  it('четыре кнопки класса вызывают PATCH-обработчик', () => {
    let got: [string, string] | null = null;
    const tr = deviceRow(base, (id, klass) => {
      got = [id, klass];
    });
    const buttons = [...tr.querySelectorAll('button')];
    expect(buttons).toHaveLength(4);
    const guest = buttons.find((b) => b.textContent === 'Гость') as HTMLButtonElement;
    guest.click();
    expect(got).toEqual(['00:00:00:00:00:0b', 'guest']);
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
