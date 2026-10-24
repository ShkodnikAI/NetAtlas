// Тесты экрана «Безопасность» (NR-010).

import { describe, expect, it } from 'vitest';
import type { SecurityGroup, SecuritySummary } from './api';
import {
  checkLine,
  checkStatusName,
  renderComputers,
  renderCounts,
  renderGroups,
  renderScore,
  renderSecurity,
  renderSecurityCard,
  scoreText,
} from './security';

const group = (rule: string, sev: string, where: string[]): SecurityGroup => ({
  rule_id: rule,
  severity: sev,
  title: 'Включён устаревший протокол SMBv1',
  basis: 'CIS Microsoft Windows Benchmark, раздел «SMB Server»',
  advice: 'Отключите компоненты SMB 1.0.',
  weight: 25,
  where,
});

const summary: SecuritySummary = {
  score: 75,
  generated_at: '2026-10-24T12:00:00Z',
  counts: { critical: 1, warning: 2, info: 0 },
  unknown_checks: 1,
  computers: [{ id: 'agent:one', hostname: 'БУХ-02', score: 75, worst: 'critical', unknown_checks: 1 }],
  findings: [group('sec_smbv1_enabled', 'critical', ['БУХ-02', 'БУХ-03'])],
  network: [group('sec_snmp_v2c_enabled', 'warning', ['sw-core'])],
};

describe('scoreText', () => {
  it('число', () => {
    expect(scoreText(78)).toBe('78');
  });
  it('нет данных — не «всё безопасно»', () => {
    expect(scoreText(null)).toBe('нет данных');
  });
});

describe('checkStatusName', () => {
  it('известные статусы', () => {
    expect(checkStatusName('pass')).toBe('норма');
    expect(checkStatusName('fail')).toBe('замечание');
    expect(checkStatusName('unknown')).toBe('не определено');
  });
  it('неизвестный статус — как есть', () => {
    expect(checkStatusName('weird')).toBe('weird');
  });
});

describe('renderScore', () => {
  it('оценка и полоса', () => {
    const root = document.createElement('div');
    renderScore(root, 78);
    expect(root.textContent).toContain('78');
    const fill = root.querySelector('.sec-score-fill') as HTMLElement;
    expect(fill.style.width).toBe('78%');
  });
  it('низкая оценка — критичный цвет', () => {
    const root = document.createElement('div');
    renderScore(root, 30);
    expect((root.querySelector('.sec-score-fill') as HTMLElement).classList.contains('fill-critical')).toBe(true);
  });
  it('null — «нет данных»', () => {
    const root = document.createElement('div');
    renderScore(root, null);
    expect(root.textContent).toContain('нет данных');
  });
});

describe('renderCounts', () => {
  it('счётчики и unknown', () => {
    const root = document.createElement('div');
    renderCounts(root, { critical: 1, warning: 2, info: 0 }, 3);
    expect(root.textContent).toContain('Критичные');
    expect(root.textContent).toContain('Не определено');
    expect(root.textContent).toContain('3');
  });
  it('без unknown — плашки нет', () => {
    const root = document.createElement('div');
    renderCounts(root, { critical: 0, warning: 0, info: 0 }, 0);
    expect(root.textContent).not.toContain('Не определено');
  });
});

describe('renderGroups', () => {
  it('замечания с основанием и списком компьютеров', () => {
    const root = document.createElement('div');
    renderGroups(root, [group('sec_smbv1_enabled', 'critical', ['БУХ-02', 'БУХ-03'])]);
    expect(root.textContent).toContain('Критичное');
    expect(root.textContent).toContain('Основание:');
    expect(root.textContent).toContain('БУХ-02, БУХ-03');
  });
  it('пусто — «замечаний нет»', () => {
    const root = document.createElement('div');
    renderGroups(root, []);
    expect(root.textContent).toContain('замечаний нет');
  });
});

describe('renderComputers', () => {
  it('строки с оценками и клик', () => {
    const root = document.createElement('div');
    let clicked = '';
    renderComputers(root, summary.computers, (id) => {
      clicked = id;
    });
    const row = root.querySelector('tbody tr') as HTMLElement;
    expect(row.textContent).toContain('БУХ-02');
    expect(row.textContent).toContain('75');
    row.click();
    expect(clicked).toBe('agent:one');
  });
});

describe('checkLine', () => {
  it('статус, имя, деталь', () => {
    const line = checkLine({ id: 'smbv1', status: 'fail', detail: 'SMBv1 включён' });
    expect(line.textContent).toContain('замечание');
    expect(line.textContent).toContain('smbv1');
    expect(line.textContent).toContain('SMBv1 включён');
  });
  it('unknown — не «норма»', () => {
    const line = checkLine({ id: 'bitlocker', status: 'unknown' });
    expect(line.textContent).toContain('не определено');
  });
});

describe('renderSecurityCard', () => {
  it('проверки, замечания, порты, возврат', () => {
    const root = document.createElement('div');
    let back = false;
    renderSecurityCard(
      root,
      {
        id: 'agent:one',
        hostname: 'БУХ-02',
        score: 80,
        collected_at: '2026-10-24T12:00:00Z',
        checks: [
          { id: 'firewall', status: 'fail', detail: 'профиль выключен: Public' },
          { id: 'ports', status: 'pass', detail: 'слушающих портов: 1' },
        ],
        findings: [{
          rule_id: 'sec_firewall_off', severity: 'critical', fact: 'Брандмауэр выключен',
          source: 'agent:check firewall @ 2026-10-24', advice: 'Включите брандмауэр.',
          basis: 'CIS, раздел «Windows Firewall»', weight: 20, priority: 20,
        }],
        ports: [{ local_address: '0.0.0.0', local_port: 3389, process: 'TermService' }],
      },
      () => {
        back = true;
      },
    );
    expect(root.textContent).toContain('Безопасность: БУХ-02');
    expect(root.textContent).toContain('оценка 80 / 100');
    expect(root.textContent).toContain('Слушающие порты (1)');
    expect(root.textContent).toContain('TermService');
    (root.querySelector('.ghost') as HTMLButtonElement).click();
    expect(back).toBe(true);
  });
});

describe('renderSecurity', () => {
  it('весь экран: оценка, компьютеры, замечания, сеть', () => {
    const root = document.createElement('div');
    renderSecurity(root, summary, null, { root, onComputer: () => undefined });
    expect(root.textContent).toContain('Общая оценка');
    expect(root.textContent).toContain('Компьютеры');
    expect(root.textContent).toContain('Сетевые устройства');
    expect(root.textContent).toContain('sw-core');
  });
  it('клик по компьютеру доходит до колбэка', () => {
    const root = document.createElement('div');
    let clicked = '';
    renderSecurity(root, summary, null, {
      root,
      onComputer: (id) => {
        clicked = id;
      },
    });
    (root.querySelector('tbody tr') as HTMLElement).click();
    expect(clicked).toBe('agent:one');
  });
  it('пустая сводка — экран живой', () => {
    const root = document.createElement('div');
    const empty: SecuritySummary = {
      score: null, generated_at: '', counts: {}, unknown_checks: 0,
      computers: [], findings: [], network: [],
    };
    renderSecurity(root, empty, null, { root, onComputer: () => undefined });
    expect(root.textContent).toContain('нет компьютеров с данными');
    expect(root.textContent).toContain('замечаний нет');
  });
});
