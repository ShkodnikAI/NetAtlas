// Тесты детерминированной раскладки (NR-032 п.4): шлюз/роутер по
// центру сверху, ряды по типам, шаг ряда по ширине самой длинной
// подписи, порядок внутри ряда по id, сохранённые позиции не трогаются.

import { describe, expect, it } from 'vitest';
import {
  GRID_STEP_Y,
  NODE_GAP,
  NODE_SIZE,
  arrangeGrid,
  measureLabel,
  rowRank,
  type GridKindNode,
} from './layout';

function n(id: string, kind: string, label = id): GridKindNode {
  return { id, kind, label };
}

// stepOfLabel — шаг ряда, который arrangeGrid вычислит для подписи.
function stepOfLabel(label: string): number {
  return Math.max(NODE_SIZE.width + NODE_GAP, measureLabel(label).width + NODE_GAP * 2);
}

describe('rowRank', () => {
  it('порядок: роутеры и коммутаторы, серверы, компьютеры, принтеры, телефоны, прочее', () => {
    expect(rowRank('router')).toBeLessThan(rowRank('switch'));
    expect(rowRank('switch')).toBeLessThan(rowRank('server'));
    expect(rowRank('server')).toBeLessThan(rowRank('device'));
    expect(rowRank('device')).toBeLessThan(rowRank('printer'));
    expect(rowRank('printer')).toBeLessThan(rowRank('phone'));
    expect(rowRank('phone')).toBeLessThan(rowRank('iot'));
    expect(rowRank('iot')).toBeLessThan(rowRank('самозванец'));
  });
});

describe('arrangeGrid', () => {
  it('роутер в первом ряду, остальные в своих рядах по вертикали', () => {
    const grid = arrangeGrid(
      [
        n('a', 'device'),
        n('b', 'printer'),
        n('c', 'router'),
        n('d', 'phone'),
        n('e', 'server'),
      ],
      new Set(),
    );
    // Роутер сверху.
    const router = grid.get('c');
    expect(router).toBeDefined();
    for (const [id, p] of grid) {
      if (id === 'c') continue;
      expect(p.y).toBeGreaterThan((router as { y: number }).y);
    }
    // Ряды совпадают по типам: сервер и компьютер — на разной высоте.
    expect(grid.get('e')?.y).not.toBe(grid.get('a')?.y);
    // Принтер и телефон — тоже в разных рядах (принтер выше).
    expect((grid.get('b')?.y ?? 0)).toBeLessThan((grid.get('d')?.y ?? 0));
  });

  it('узлы одного ряда на равных координатах Y (сетка), X с равным шагом', () => {
    const grid = arrangeGrid(
      [n('01', 'device'), n('02', 'device'), n('03', 'device'), n('04', 'device')],
      new Set(),
    );
    const ys = [...grid.values()].map((p) => p.y);
    expect(new Set(ys).size).toBe(1);
    const xs = [...grid.values()].map((p) => p.x).sort((a, b) => a - b);
    const first = xs[0] ?? 0;
    const second = xs[1] ?? first;
    const step = second - first;
    for (let i = 1; i < xs.length; i++) {
      expect((xs[i] ?? 0) - (xs[i - 1] ?? 0)).toBeCloseTo(step, 6);
    }
  });

  it('шаг ряда не меньше ширины самой длинной подписи в ряду', () => {
    const short = arrangeGrid([n('a', 'device', 'ab'), n('b', 'device', 'cd')], new Set());
    const long = arrangeGrid(
      [n('a', 'device', 'очень длинная подпись принтера канцелярии'), n('b', 'device', 'cd')],
      new Set(),
    );
    const stepOf = (g: Map<string, { x: number; y: number }>): number => {
      const xs = [...g.values()].map((p) => p.x).sort((a, b) => a - b);
      return (xs[1] ?? 0) - (xs[0] ?? 0);
    };
    expect(stepOf(long)).toBeGreaterThan(stepOf(short));
  });

  it('порядок входа не влияет на результат (детерминированность)', () => {
    const base = [n('a', 'device'), n('b', 'printer'), n('c', 'router')];
    const one = arrangeGrid(base, new Set());
    const two = arrangeGrid([...base].reverse(), new Set());
    expect(one.get('a')).toEqual(two.get('a'));
    expect(one.get('b')).toEqual(two.get('b'));
    expect(one.get('c')).toEqual(two.get('c'));
  });

  it('сохранённые позиции владельца исключаются из раскладки', () => {
    const grid = arrangeGrid(
      [n('a', 'device'), n('b', 'device'), n('c', 'router')],
      new Set(['a']),
    );
    expect(grid.has('a')).toBe(false);
    expect(grid.has('b')).toBe(true);
    expect(grid.has('c')).toBe(true);
  });

  it('ряды идут сверху вниз с постоянным вертикальным шагом', () => {
    const grid = arrangeGrid(
      [n('r', 'router'), n('s', 'server'), n('d', 'device'), n('p', 'printer')],
      new Set(),
    );
    expect((grid.get('s')?.y ?? 0) - (grid.get('r')?.y ?? 0)).toBeCloseTo(GRID_STEP_Y, 6);
    expect((grid.get('d')?.y ?? 0) - (grid.get('s')?.y ?? 0)).toBeCloseTo(GRID_STEP_Y, 6);
  });

  // NR-034 п.2: 11 узлов одного типа не должны вытягиваться в строку
  // шириной в экран — ряд переносится после N колонок.
  it('ряд шире maxWidth переносится на следующую строку того же ряда', () => {
    const nodes = ['01', '02', '03', '04', '05', '06'].map((id) =>
      n(id, 'device', `устройство-${id}`),
    );
    // Без ограничения — одна строка.
    const wide = arrangeGrid(nodes, new Set());
    expect(new Set([...wide.values()].map((p) => p.y)).size).toBe(1);
    // Ширина ровно на 3 колонки — две строки по 3.
    const step = stepOfLabel('устройство-01');
    const wrapped = arrangeGrid(nodes, new Set(), 3 * step);
    const first = nodes.slice(0, 3).map((x) => wrapped.get(x.id));
    const second = nodes.slice(3).map((x) => wrapped.get(x.id));
    for (const p of first) {
      expect(p?.y).toBe(first[0]?.y);
    }
    for (const p of second) {
      expect(p?.y).toBe((first[0]?.y ?? 0) + GRID_STEP_Y);
    }
    // X второй строки совпадает с X первой (колонка шлюза свободна).
    expect(second[0]?.x).toBe(first[0]?.x);
  });

  it('перенос отодвигает следующие ряды вниз (пересечений нет)', () => {
    const step = stepOfLabel('компьютер-01');
    const grid = arrangeGrid(
      [
        n('r', 'router'),
        ...['01', '02', '03', '04', '05', '06'].map((id) => n(id, 'device', `компьютер-${id}`)),
        n('p', 'printer'),
      ],
      new Set(),
      3 * step,
    );
    // Роутер сверху; после переноса ряда device следующие ряды
    // начинаются после последней строки device.
    expect(grid.get('r')?.y ?? 0).toBeLessThan(grid.get('01')?.y ?? 0);
    // Шесть device в две строки: принтер ниже обеих строк device.
    expect(grid.get('p')?.y ?? 0).toBeGreaterThan(grid.get('06')?.y ?? 0);
  });

  it('узкий максимум не даёт пустых колонок (одна колонка минимум)', () => {
    const grid = arrangeGrid([n('a', 'device'), n('b', 'device')], new Set(), 1);
    expect(grid.get('a')?.x).toBe(grid.get('b')?.x);
    expect((grid.get('b')?.y ?? 0) - (grid.get('a')?.y ?? 0)).toBeCloseTo(GRID_STEP_Y, 6);
  });
});
