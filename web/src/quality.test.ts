// Тесты экрана «Качество сети» (NR-008).

import { describe, expect, it } from 'vitest';
import { cellWorst, renderBottlenecks, renderQualityMatrix, svgPolyline, type Bottleneck, type QualityCell } from './quality';

const cell: QualityCell = {
  agent_id: 'agent:one',
  target: '192.168.1.1',
  latest: { latency: 12.5, loss: 0.01, jitter: 3 },
  worst: 'ok',
};

describe('cellWorst', () => {
  it('норма', () => {
    expect(cellWorst(cell.latest)).toBe('ok');
  });
  it('потери >2% — предупреждение', () => {
    expect(cellWorst({ loss: 0.03 })).toBe('warning');
  });
  it('потери >5% — критично', () => {
    expect(cellWorst({ loss: 0.06 })).toBe('critical');
  });
  it('задержка >50 мс — предупреждение', () => {
    expect(cellWorst({ latency: 60 })).toBe('warning');
  });
});

describe('renderQualityMatrix', () => {
  it('таблица с ячейками', () => {
    const root = document.createElement('div');
    renderQualityMatrix(root, [cell]);
    const rows = root.querySelectorAll('tbody tr');
    expect(rows.length).toBe(1);
    const row0 = rows[0] as HTMLElement;
    expect(row0.textContent).toContain('192.168.1.1');
    expect(row0.textContent).toContain('12.5');
  });
  it('пусто — нет данных', () => {
    const root = document.createElement('div');
    renderQualityMatrix(root, []);
    expect(root.textContent).toContain('нет данных');
  });
});

describe('svgPolyline', () => {
  it('три линии (avg/p95/max)', () => {
    const pts = [
      { window: '2026-10-24T01:00', avg: 10, p95: 20, max: 30 },
      { window: '2026-10-24T02:00', avg: 15, p95: 25, max: 40 },
    ];
    const svg = svgPolyline(pts, 600, 120);
    expect(svg.querySelectorAll('polyline').length).toBe(3);
  });
  it('мало точек — пустой график', () => {
    const svg = svgPolyline([], 600, 120);
    expect(svg.querySelectorAll('polyline').length).toBe(0);
  });
});

describe('renderBottlenecks', () => {
  it('список с рекомендациями', () => {
    const root = document.createElement('div');
    const b: Bottleneck[] = [
      { agent_id: 'a', hostname: 'PC-1', finding: { rule_id: 'loss_high', severity: 'warning', fact: 'потери до 192.168.1.1 — 3.0%', source: 'metrics.loss', advice: 'Проверьте кабели.', priority: 60 } },
    ];
    renderBottlenecks(root, b);
    expect(root.textContent).toContain('PC-1: потери');
    expect(root.textContent).toContain('рекомендация: Проверьте кабели.');
  });
  it('нет узких мест', () => {
    const root = document.createElement('div');
    renderBottlenecks(root, []);
    expect(root.textContent).toContain('не найдено');
  });
});
