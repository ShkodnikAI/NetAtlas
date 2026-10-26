// Тесты раскладки карты (NR-031 п.4): оценка подписи, сетка для
// одиночных узлов, разведение пересечений.

import { describe, expect, it } from 'vitest';
import {
  GRID_COLUMNS,
  GRID_STEP_X,
  GRID_STEP_Y,
  LABEL_MAX_WIDTH,
  anyOverlap,
  boxOf,
  deoverlap,
  gridPlacement,
  gridPositions,
  measureLabel,
  overlapArea,
  type Positioned,
} from './layout';

const pos = (id: string, x: number, y: number, label: string): Positioned => ({
  id,
  x,
  y,
  label: measureLabel(label),
});

describe('measureLabel', () => {
  it('короткая подпись — одна строка', () => {
    const s = measureLabel('router-01');
    expect(s.height).toBe(14);
    expect(s.width).toBeLessThanOrEqual(LABEL_MAX_WIDTH);
  });

  it('длинная подпись переносится по ширине', () => {
    const long = 'A'.repeat(60);
    const s = measureLabel(long);
    expect(s.width).toBe(LABEL_MAX_WIDTH);
    expect(s.height).toBeGreaterThan(14);
  });
});

describe('gridPositions (NR-031 п.4)', () => {
  it('узлы идут по сетке слева направо, шаг учитывает ширину подписи', () => {
    const ids = ['a', 'b', 'c', 'd', 'e', 'f'];
    const grid = gridPositions(ids, gridPlacement(null));
    expect(grid.size).toBe(ids.length);
    expect(grid.get('a')).toEqual({ x: 0, y: 0 });
    expect(grid.get('b')?.x).toBeGreaterThanOrEqual(GRID_STEP_X);
    // Шестой узел — вторая строка сетки (5 колонок).
    expect(grid.get('f')?.y).toBeGreaterThanOrEqual(GRID_STEP_Y);
    expect(GRID_COLUMNS).toBeGreaterThan(1);
  });

  it('сетка одиночных уходит правее связанной части', () => {
    const connected = { x1: 0, y1: 0, x2: 300, y2: 200 };
    const p = gridPlacement(connected);
    expect(p.originX).toBeGreaterThan(connected.x2);
  });
});

describe('deoverlap (NR-031 п.4)', () => {
  it('узлы в одной точке расходятся без пересечений', () => {
    const nodes = [
      pos('a', 0, 0, 'aa:bb:cc:dd:ee:ff'),
      pos('b', 0, 0, 'aa:bb:cc:dd:ee:01'),
      pos('c', 0, 0, 'aa:bb:cc:dd:ee:02'),
      pos('d', 0, 0, 'aa:bb:cc:dd:ee:03'),
      pos('e', 0, 0, 'aa:bb:cc:dd:ee:04'),
      pos('f', 0, 0, 'aa:bb:cc:dd:ee:05'),
    ];
    deoverlap(nodes);
    expect(anyOverlap(nodes)).toBe(false);
  });

  it('сетка из 12 узлов с длинными MAC не пересекается и после сведения', () => {
    const grid = gridPositions(
      Array.from({ length: 12 }, (_, i) => `02:00:00:00:0${Math.floor(i / 10)}:0${i % 10}`),
      gridPlacement(null),
    );
    const nodes: Positioned[] = [...grid.entries()].map(([id, p]) =>
      pos(id, p.x, p.y, id),
    );
    deoverlap(nodes);
    expect(anyOverlap(nodes)).toBe(false);
  });

  it('узлы без пересечений не сдвигаются', () => {
    const nodes = [pos('a', 0, 0, 'a'), pos('b', 500, 500, 'b')];
    const before = nodes.map((n) => ({ x: n.x, y: n.y }));
    deoverlap(nodes);
    expect(nodes.map((n) => ({ x: n.x, y: n.y }))).toEqual(before);
  });
});

describe('boxOf / overlapArea', () => {
  it('габарит включает узел и подпись под ним', () => {
    const b = boxOf(0, 0, { width: 100, height: 14 });
    expect(b.y1).toBeLessThan(0);
    expect(b.y2).toBeGreaterThan(0);
    expect(b.x1).toBeLessThan(-44 / 2);
  });

  it('overlapArea нулевая для раздвинутых прямоугольников', () => {
    const a = { x1: 0, y1: 0, x2: 10, y2: 10 };
    expect(overlapArea(a, { x1: 20, y1: 20, x2: 30, y2: 30 })).toBe(0);
    expect(overlapArea(a, { x1: 5, y1: 5, x2: 15, y2: 15 })).toBe(25);
  });
});
