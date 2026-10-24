// Тесты экрана «Диски» (NR-009): строки томов, полоски заполнения,
// экранирование.

import { describe, expect, it } from 'vitest';
import type { DiskView } from './api';
import { barFill, diskRow, renderDisks } from './disks';

const disk: DiskView = {
  agent_id: 'agent:one',
  hostname: 'PC-1',
  drive: 'C',
  label: 'Система',
  file_system: 'NTFS',
  capacity_bytes: 1000000000000,
  used_bytes: 800000000000,
  free_pct: 20,
  forecast: { days_to_full: 30, confidence: 0.98 },
};

describe('barFill', () => {
  it('ширина = доля занятого', () => {
    const bar = barFill(20);
    const inner = bar.querySelector('.fill-bar-inner') as HTMLElement;
    expect(parseFloat(inner.style.width)).toBeCloseTo(80);
    expect(inner.className).not.toContain('danger');
  });
  it('мало места — danger', () => {
    const bar = barFill(5);
    expect((bar.querySelector('.fill-bar-inner') as HTMLElement).className).toContain('danger');
  });
});

describe('diskRow', () => {
  it('хост, том, заполнение и прогноз текстом', () => {
    const row = diskRow(disk);
    expect(row.textContent).toContain('PC-1 · том C');
    expect(row.textContent).toContain('свободно 20.0%');
    expect(row.textContent).toContain('заполнится через 30 дн.');
  });
  it('недостаточно данных — причина', () => {
    const row = diskRow({ ...disk, forecast: { insufficient: 'мало точек: 2 из 7' } });
    expect(row.textContent).toContain('прогноз: нет (мало точек: 2 из 7)');
  });
  it('подпись недоверенная: HTML как текст', () => {
    const row = diskRow({ ...disk, hostname: '<script>alert(1)</script>' });
    expect(row.querySelector('script')).toBeNull();
    expect(row.textContent).toContain('<script>');
  });
});

describe('renderDisks', () => {
  it('список томов', () => {
    const root = document.createElement('div');
    renderDisks(root, [disk, { ...disk, drive: 'D' }]);
    expect(root.querySelectorAll('.disk-row').length).toBe(2);
  });
  it('пусто — нет данных', () => {
    const root = document.createElement('div');
    renderDisks(root, []);
    expect(root.textContent).toContain('нет данных');
  });
});
