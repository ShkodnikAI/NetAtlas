// Тесты фоновой сетки из точек (NR-035 п.2, NR-038 п.2): тайл сетки
// следует масштабу и панораме карты, шаг равен мелкой сетке 20×20;
// при масштабе меньше 0.6 видна каждая пятая точка; видимость требует
// обоих переключателей.

import { describe, expect, it } from 'vitest';
import { GRID_STEP } from './layout';
import { GRID_RARE_FACTOR, applyGridPaint, gridPaint, gridVisible } from './mapgrid';

describe('gridPaint', () => {
  it('размер тайла = мелкая сетка × масштаб (NR-038 п.2)', () => {
    const p = gridPaint(1, { x: 0, y: 0 });
    expect(p.sizeX).toBe(GRID_STEP);
    expect(p.sizeY).toBe(GRID_STEP);
  });

  it('масштаб 0.8 сжимает тайл, панорама смещает фон', () => {
    const p = gridPaint(0.8, { x: 120, y: -45 });
    expect(p.sizeX).toBeCloseTo(GRID_STEP * 0.8, 6);
    expect(p.sizeY).toBeCloseTo(GRID_STEP * 0.8, 6);
    expect(p.posX).toBe(120);
    expect(p.posY).toBe(-45);
  });

  it('при масштабе меньше 0.6 показывается каждая пятая точка (NR-038 п.2)', () => {
    const rare = gridPaint(0.5, { x: 0, y: 0 });
    expect(rare.sizeX).toBeCloseTo(GRID_STEP * GRID_RARE_FACTOR * 0.5, 6);
    expect(rare.sizeY).toBeCloseTo(GRID_STEP * GRID_RARE_FACTOR * 0.5, 6);
    // На границе и выше — обычная плотность.
    const edge = gridPaint(0.6, { x: 0, y: 0 });
    expect(edge.sizeX).toBeCloseTo(GRID_STEP * 0.6, 6);
  });

  it('applyGridPaint наливает свойства в DOM-слой', () => {
    const div = document.createElement('div');
    applyGridPaint(div, gridPaint(2, { x: 10, y: 20 }));
    expect(div.style.backgroundSize).toBe(`${GRID_STEP * 2}px ${GRID_STEP * 2}px`);
    expect(div.style.backgroundPosition).toBe('10px 20px');
  });
});

describe('gridVisible', () => {
  const box = (checked: boolean): HTMLInputElement => {
    const el = document.createElement('input');
    el.type = 'checkbox';
    el.checked = checked;
    return el;
  };

  it('сетка видна только при включённых обоих переключателях', () => {
    expect(gridVisible(box(true), box(true))).toBe(true);
    expect(gridVisible(box(false), box(true))).toBe(false);
    expect(gridVisible(box(true), box(false))).toBe(false);
    expect(gridVisible(box(false), box(false))).toBe(false);
  });
});
