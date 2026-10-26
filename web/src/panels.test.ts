// Тесты панели: данные из API недоверенные — подписи вставляются как
// текст (textContent), не как HTML; действия доступны с клавиатуры.

import { describe, expect, it } from 'vitest';
import type { DeviceInfo } from './api';
import { fillEdit, fillOverview, fillNet, setObservations } from './panels';

function info(patch: Partial<DeviceInfo>): DeviceInfo {
  return {
    id: '00:00:00:00:00:0b',
    hostname: 'printer',
    class: 'unknown',
    ips: ['10.0.0.11'],
    names: [],
    observations: [{ source: 'arp', seen: '2026-10-23T12:00:00Z' }],
    vendor: 'Cisco',
    ssid: '',
    manual: false,
    verified: true,
    ...patch,
  };
}

describe('fillOverview', () => {
  it('вставляет значения как текст: HTML в имени не исполняется', () => {
    const page = document.createElement('div');
    fillOverview(page, info({ hostname: '<img src=x onerror=alert(1)>', id: 'manual:1' }), 'printer');
    const html = page.innerHTML;
    expect(html).not.toContain('<img');
    expect(page.textContent).toContain('<img src=x onerror=alert(1)>');
  });

  it('метки «вручную» и «не проверен» показываются', () => {
    const page = document.createElement('div');
    fillOverview(page, info({ manual: true, verified: false }), 'device');
    expect(page.textContent).toContain('вручную');
    expect(page.textContent).toContain('не проверен');
  });
});

describe('fillEdit', () => {
  it('кнопка удаления есть только у ручного элемента', () => {
    const manual = document.createElement('div');
    fillEdit(manual, info({ manual: true, id: 'manual:1' }), {
      onRename: () => {}, onClass: () => {}, onKind: () => {}, onVerify: () => {}, onDelete: () => {},
    });
    expect(manual.textContent).toContain('Удалить ручной элемент');

    const found = document.createElement('div');
    fillEdit(found, info({ manual: false }), {
      onRename: () => {}, onClass: () => {}, onKind: () => {}, onVerify: () => {}, onDelete: () => {},
    });
    expect(found.textContent).not.toContain('Удалить ручной элемент');
  });

  it('классы перечислены и выбран текущий', () => {
    const page = document.createElement('div');
    fillEdit(page, info({ class: 'guest' }), {
      onRename: () => {}, onClass: () => {}, onKind: () => {}, onVerify: () => {}, onDelete: () => {},
    });
    const select = page.querySelector('select') as HTMLSelectElement;
    expect(select.options).toHaveLength(4);
    expect(select.value).toBe('guest');
  });

  it('переименование зовёт обработчик с новым именем', () => {
    const page = document.createElement('div');
    let got = '';
    fillEdit(page, info({ hostname: 'старое' }), {
      onRename: (_id, name) => {
        got = name;
      },
      onClass: () => {},
      onKind: () => {},
      onVerify: () => {},
      onDelete: () => {},
    });
    const input = page.querySelector('input[type="text"]') as HTMLInputElement;
    input.value = 'новое';
    const save = [...page.querySelectorAll('button')].find((b) => b.textContent?.includes('Сохранить'));
    (save as HTMLButtonElement).click();
    expect(got).toBe('новое');
  });
});

describe('fillNet', () => {
  it('показывает связи узла и наблюдения', () => {
    const page = document.createElement('div');
    setObservations([{ source: 'arp', seen: '2026-10-23T12:00:00Z' }]);
    fillNet(page, '00:00:00:00:00:0b', {
      nodes: [],
      links: [
        {
          a: '00:00:00:00:00:01', aPort: 'Gi0/1',
          b: '00:00:00:00:00:0b', bPort: 'eth0',
          source: 'manual', manual: true, verified: false,
        },
      ],
    });
    expect(page.textContent).toContain('00:00:00:00:00:01 (eth0)');
    expect(page.textContent).toContain('вручную');
    expect(page.textContent).toContain('arp');
  });
});

describe('тип узла: автоматический вывод и ручной выбор (NR-032 п.1)', () => {
  it('автоматический тип помечен «определён автоматически, изменить»', () => {
    const page = document.createElement('div');
    fillOverview(page, info({ kind: 'printer', kindAuto: 'printer' }), 'printer');
    const dd = page.querySelector('dd');
    expect(dd?.textContent).toContain('принтер');
    expect(dd?.textContent).toContain('определён автоматически');
    const change = dd?.querySelector('button');
    expect(change?.textContent).toBe('изменить');
    // Клик «изменить» зовёт колбэк (переход на вкладку «Правка»).
    let called = false;
    fillOverview(page, info({ kind: 'printer', kindAuto: 'printer' }), 'printer', () => {
      called = true;
    });
    (page.querySelector('dd button') as HTMLButtonElement).click();
    expect(called).toBe(true);
  });

  it('ручной тип помечен «указан вручную» и не даёт пометку автомата', () => {
    const page = document.createElement('div');
    fillOverview(page, info({ kind: 'server', kindAuto: 'printer', kindManual: true }), 'server');
    const dd = page.querySelector('dd');
    expect(dd?.textContent).toContain('сервер');
    expect(dd?.textContent).toContain('указан вручную');
    expect(dd?.textContent).not.toContain('определён автоматически');
  });

  it('в «Правке» есть выбор типа с новыми kind и кнопкой смены', () => {
    const page = document.createElement('div');
    fillEdit(page, info({ kind: 'phone' }), {
      onRename: () => {},
      onClass: () => {},
      onKind: (id, kind) => {
        // Ручной тип уходит в обработчик с id узла.
        expect(id).toBe('00:00:00:00:00:0b');
        expect(kind).toBe('tv');
      },
      onVerify: () => {},
      onDelete: () => {},
    });
    const select = page.querySelector('#edit-kind') as HTMLSelectElement;
    expect(select).not.toBeNull();
    const kinds = [...select.options].map((o) => o.value);
    for (const k of ['device', 'printer', 'phone', 'iot', 'tv', 'router']) {
      expect(kinds).toContain(k);
    }
    expect(select.value).toBe('phone');
    select.value = 'tv';
    const apply = [...page.querySelectorAll('button')].find((b) =>
      b.textContent?.includes('Сменить тип'),
    );
    (apply as HTMLButtonElement).click();
  });
});
