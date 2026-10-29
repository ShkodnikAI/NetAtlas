// Тесты точек изгиба (NR-038 п.1): ортогональная ломаная через точки
// по порядку, точное представление вершин в wts/dss cytoscape,
// привязка к мелкой сетке 20×20.

import { describe, expect, it } from 'vitest';
import { GRID_STEP, snapToGrid } from './layout';
import {
  dedupPoints,
  orthogonalPolyline,
  pointsFromWeights,
  snapPoint,
  toWeightsDistances,
  waypointId,
} from './waypoints';

describe('orthogonalPolyline', () => {
  it('без точек — прямая из конца в конец', () => {
    const line = orthogonalPolyline({ x: 0, y: 0 }, { x: 200, y: 0 }, []);
    expect(line).toEqual([
      { x: 0, y: 0 },
      { x: 200, y: 0 },
    ]);
  });

  it('точка изгиба встаёт на излом: вход горизонталью, выход вертикалью', () => {
    const line = orthogonalPolyline(
      { x: 0, y: 0 },
      { x: 200, y: 100 },
      [{ x: 80, y: 100 }],
    );
    // Вертикаль от источника до y=100, горизонталь к точке, вертикаль
    // от точки к цели... колени: (0,100) → (80,100) → (80,200)?
    expect(line[0]).toEqual({ x: 0, y: 0 });
    // Ломаная проходит через точку изгиба.
    expect(line).toContainEqual({ x: 80, y: 100 });
    // Все сегменты ортогональны.
    for (let i = 1; i < line.length; i++) {
      const a = line[i - 1] as { x: number; y: number };
      const b = line[i] as { x: number; y: number };
      expect(a.x === b.x || a.y === b.y).toBe(true);
    }
    expect(line[line.length - 1]).toEqual({ x: 200, y: 100 });
  });

  it('несколько точек проходятся по порядку', () => {
    const line = orthogonalPolyline(
      { x: 0, y: 0 },
      { x: 300, y: 300 },
      [
        { x: 100, y: 40 },
        { x: 200, y: 140 },
      ],
    );
    expect(line).toContainEqual({ x: 100, y: 40 });
    expect(line).toContainEqual({ x: 200, y: 140 });
    const first = line.findIndex((p) => p.x === 100 && p.y === 40);
    const second = line.findIndex((p) => p.x === 200 && p.y === 140);
    expect(first).toBeGreaterThan(-1);
    expect(second).toBeGreaterThan(first);
    for (let i = 1; i < line.length; i++) {
      const a = line[i - 1] as { x: number; y: number };
      const b = line[i] as { x: number; y: number };
      expect(a.x === b.x || a.y === b.y).toBe(true);
    }
  });

  it('совпадающие вершины схлопываются', () => {
    expect(
      dedupPoints([
        { x: 0, y: 0 },
        { x: 0, y: 0 },
        { x: 20, y: 0 },
        { x: 20, y: 0 },
      ]),
    ).toEqual([
      { x: 0, y: 0 },
      { x: 20, y: 0 },
    ]);
    // Вырожденный случай: точка изгиба на прямой остаётся вершиной
    // (узел-точка рисуется на линии, сегменты прямые).
    const line = orthogonalPolyline({ x: 0, y: 0 }, { x: 200, y: 0 }, [{ x: 100, y: 0 }]);
    expect(line).toEqual([
      { x: 0, y: 0 },
      { x: 100, y: 0 },
      { x: 200, y: 0 },
    ]);
  });
});

describe('toWeightsDistances / pointsFromWeights', () => {
  it('wts/dss восстанавливают вершины точно (в обе стороны)', () => {
    const src = { x: 40, y: 40 };
    const dst = { x: 240, y: 280 };
    const inner = [
      { x: 40, y: 160 },
      { x: 140, y: 160 },
      { x: 140, y: 280 },
    ];
    const { wts, dss } = toWeightsDistances(src, dst, inner);
    expect(wts).toHaveLength(3);
    const back = pointsFromWeights(src, dst, wts, dss);
    for (let i = 0; i < inner.length; i++) {
      expect(back[i]?.x).toBeCloseTo((inner[i] as { x: number }).x, 6);
      expect(back[i]?.y).toBeCloseTo((inner[i] as { y: number }).y, 6);
    }
  });

  it('наклонная ось: точка на стороне восстанавливается с нормалью', () => {
    const src = { x: 0, y: 0 };
    const dst = { x: 100, y: 100 };
    const { wts, dss } = toWeightsDistances(src, dst, [{ x: 40, y: 80 }]);
    const back = pointsFromWeights(src, dst, wts, dss);
    expect(back[0]?.x).toBeCloseTo(40, 6);
    expect(back[0]?.y).toBeCloseTo(80, 6);
  });
});

describe('snapPoint (NR-038 п.2)', () => {
  it('привязывает к узлу мелкой сетки 20×20', () => {
    expect(snapPoint({ x: 21, y: 39 })).toEqual({ x: 20, y: 40 });
    expect(snapPoint({ x: -7, y: 199 })).toEqual({ x: 0, y: 200 });
    const p = snapPoint({ x: 123.4, y: -55.6 });
    expect(Math.abs(p.x % GRID_STEP)).toBe(0);
    expect(Math.abs(p.y % GRID_STEP)).toBe(0);
    // Согласована с привязкой узлов (одна сетка).
    expect(snapPoint({ x: 333, y: 777 })).toEqual(snapToGrid(333, 777));
  });
});

describe('waypointId', () => {
  it('id узла-точки привязан к ключу связи и индексу', () => {
    expect(waypointId('a||b|', 2)).toBe('wp:a||b|:2');
  });
});
