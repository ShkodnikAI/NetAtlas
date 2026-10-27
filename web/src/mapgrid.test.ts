// Тесты фоновой сетки из точек (NR-035 п.2): тайл сетки следует
// масштабу и панораме карты, шаг равен шагу привязки; видимость
// требует обоих переключателей.

import { describe, expect, it } from 'vitest';
import { SNAP_STEP_X, SNAP_STEP_Y } from './layout';
import { applyGridPaint, gridPaint, gridVisible } from './mapgrid';

describe('gridPaint', () => {
  it('размер тайла = шаг привязки × масштаб', () => {
    const p = gridPaint(1, { x: 0, y: 0 });
    expect(p.sizeX).toBe(SNAP_STEP_X);
    expect(p.sizeY).toBe(SNAP_STEP_Y);
  });

  it('масштаб 0.8 сжимает тайл, панорама смещает фон', () => {
    const p = gridPaint(0.8, { x: 120, y: -45 });
    expect(p.sizeX).toBeCloseTo(SNAP_STEP_X * 0.8, 6);
    expect(p.sizeY).toBeCloseTo(SNAP_STEP_Y * 0.8, 6);
    expect(p.posX).toBe(120);
    expect(p.posY).toBe(-45);
  });

  it('applyGridPaint наливает свойства в DOM-слой', () => {
    const div = document.createElement('div');
    applyGridPaint(div, gridPaint(2, { x: 10, y: 20 }));
    expect(div.style.backgroundSize).toBe(`${SNAP_STEP_X * 2}px ${SNAP_STEP_Y * 2}px`);
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
