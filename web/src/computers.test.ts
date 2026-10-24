// Тесты экрана «Компьютеры» (NR-009): рендер, экранирование, нет данных.

import { describe, expect, it } from 'vitest';
import type { ComputerCard, ComputerSummary, Finding } from './api';
import { findingRow, findingsLine, forecastText, fmtBytes, renderComputerCard, renderComputers } from './computers';

const summary: ComputerSummary = {
  id: 'agent:one',
  hostname: 'PC-1',
  status: 'active',
  inventory_at: '2026-10-24T10:00:00Z',
  findings: { critical: 1, warning: 2 },
  max_priority: 1000,
  worst_days_to_full: 45,
};

const finding: Finding = {
  rule_id: 'ram_low',
  severity: 'warning',
  fact: 'ОЗУ 4.0 ГБ (модулей: 1) — ниже порога 8 ГБ',
  threshold: '>= 8 ГБ',
  source: 'hardware.total_physical_memory @ 2026-10-24T10:00:00Z',
  advice: 'Добавьте память.',
  priority: 160,
};

describe('findingsLine', () => {
  it('счётчики по серьёзности', () => {
    expect(findingsLine(summary)).toBe('критично: 1, предупреждений: 2');
  });
  it('без инвентаря — нет данных', () => {
    expect(findingsLine({ ...summary, inventory_at: undefined })).toBe('нет данных');
  });
  it('без замечаний', () => {
    expect(findingsLine({ ...summary, findings: {} })).toBe('замечаний нет');
  });
});

describe('forecastText', () => {
  it('с днями', () => {
    expect(forecastText({ days_to_full: 45 })).toBe('заполнится через 45 дн.');
  });
  it('без данных', () => {
    expect(forecastText({ insufficient: 'мало точек: 3 из 7' })).toBe('прогноз: нет (мало точек: 3 из 7)');
  });
});

describe('fmtBytes', () => {
  it('байты в ГБ', () => {
    expect(fmtBytes('17179869184')).toBe('16.0 ГБ');
  });
  it('мусор — тире', () => {
    expect(fmtBytes('не число')).toBe('—');
  });
});

describe('renderComputers', () => {
  it('таблица со строками; клик открывает карточку', () => {
    const root = document.createElement('div');
    const opened: string[] = [];
    renderComputers(root, [summary], (id) => opened.push(id));
    const rows = root.querySelectorAll('tbody tr');
    expect(rows.length).toBe(1);
    expect(rows[0].textContent).toContain('PC-1');
    expect(rows[0].textContent).toContain('критично: 1');
    (rows[0] as HTMLTableRowElement).click();
    expect(opened).toEqual(['agent:one']);
  });
  it('пустой список — нет данных', () => {
    const root = document.createElement('div');
    renderComputers(root, [], () => undefined);
    expect(root.textContent).toContain('нет данных');
  });
});

describe('renderComputerCard', () => {
  const card: ComputerCard = {
    id: 'agent:one',
    hostname: 'PC-1',
    status: 'active',
    inventory_at: '2026-10-24T10:00:00Z',
    inventory: {
      os: { caption: 'Windows 11 Pro', build_number: '26200' },
      hardware: { total_physical_memory: '17179869184', cpus: [{ name: 'Core i5', cores: 6 }] },
      disks: { volumes: [{ drive_letter: 'C', size: '1000', size_remaining: '100' }] },
    },
    findings: [finding],
    forecasts: { C: { days_to_full: 45 } },
  };

  it('вкладки присутствуют, обзор активен, замечания на месте', () => {
    const root = document.createElement('div');
    renderComputerCard(root, card, () => undefined);
    const tabs = root.querySelectorAll('.tabs2 .tab');
    expect(tabs.length).toBe(6);
    expect(root.textContent).toContain('Windows 11 Pro');
    expect(root.textContent).toContain('Том C');
    expect(root.textContent).toContain('заполнится через 45 дн.');
    // Вкладка замечаний скрыта, но контент отрисован.
    expect(root.textContent).toContain('ОЗУ 4.0 ГБ');
  });

  it('подписи недоверенные: HTML вставляется как текст', () => {
    const root = document.createElement('div');
    const xss = '<img src=x onerror=alert(1)>';
    renderComputerCard(root, { ...card, hostname: xss, findings: [{ ...finding, fact: xss }] }, () => undefined);
    expect(root.querySelector('img')).toBeNull();
    expect(root.textContent).toContain(xss);
  });

  it('без инвентаря — заглушка нет данных', () => {
    const root = document.createElement('div');
    renderComputerCard(root, { ...card, inventory: undefined, inventory_at: undefined }, () => undefined);
    expect(root.textContent).toContain('нет данных');
  });
});

describe('findingRow', () => {
  it('серьёзность, факт и совет текстом', () => {
    const row = findingRow(finding);
    expect(row.className).toContain('severity-warning');
    expect(row.textContent).toContain('предупреждение');
    expect(row.textContent).toContain('рекомендация: Добавьте память.');
  });
});
