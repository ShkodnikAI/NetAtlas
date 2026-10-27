// Тесты легенды (NR-032 п.3, п.5): типы, присутствующие на карте, в
// порядке наряда; пунктирная строка — только при предполагаемых
// связях; DOM заливается безопасно (textContent).

import { describe, expect, it } from 'vitest';
import type { Graph } from './api';
import { ASSUMED_TEXT, hasAssumedLinks, legendItems, renderLegend } from './legend';

function graph(nodes: { kind: string }[], links: { source: string }[]): Graph {
  return {
    nodes: nodes.map((n, i) => ({
      id: `node-${i}`,
      kind: n.kind,
      label: `узел ${i}`,
      manual: false,
      verified: true,
    })),
    links: links.map((l, i) => ({
      a: `node-${i}`,
      aPort: '',
      b: `node-${i + 1}`,
      bPort: '',
      source: l.source,
      manual: false,
      verified: false,
    })),
  };
}

describe('legendItems', () => {
  it('показывает только типы, которые есть на карте', () => {
    const items = legendItems(
      graph([{ kind: 'router' }, { kind: 'printer' }, { kind: 'phone' }], []),
    );
    expect(items.map((i) => i.kind)).toEqual(['router', 'printer', 'phone']);
  });

  it('порядок по наряду: роутеры и коммутаторы, серверы, компьютеры, принтеры, телефоны', () => {
    const items = legendItems(
      graph(
        [
          { kind: 'phone' },
          { kind: 'printer' },
          { kind: 'device' },
          { kind: 'server' },
          { kind: 'router' },
          { kind: 'switch' },
        ],
        [],
      ),
    );
    expect(items.map((i) => i.kind)).toEqual([
      'router',
      'switch',
      'server',
      'device',
      'printer',
      'phone',
    ]);
  });

  it('у каждого элемента есть подпись и значок роли', () => {
    const items = legendItems(graph([{ kind: 'iot' }, { kind: 'tv' }], []));
    for (const item of items) {
      expect(item.label).not.toBe('');
      expect(item.icon).toContain('data:image/svg+xml');
      // Значок роли — диск цвета группы с белым глифом (NR-036).
      const svg = decodeURIComponent(item.icon);
      expect(svg).toContain('stroke="#FFFFFF"');
      expect(svg).toMatch(/#[0-9A-Fa-f]{6}/);
    }
  });
});

describe('hasAssumedLinks', () => {
  it('истинно только для источника assumed', () => {
    expect(hasAssumedLinks(graph([], [{ source: 'assumed' }]))).toBe(true);
    expect(hasAssumedLinks(graph([], [{ source: 'fdb' }]))).toBe(false);
    expect(hasAssumedLinks(graph([], [{ source: 'lldp' }]))).toBe(false);
    expect(hasAssumedLinks(graph([], [{ source: 'manual' }]))).toBe(false);
  });
});

describe('renderLegend', () => {
  it('рисует образцы колец статусов, значки ролей и пунктирную строку при assumed-связи (NR-036 п.2)', () => {
    const box = document.createElement('div');
    renderLegend(box, graph([{ kind: 'router' }, { kind: 'printer' }], [{ source: 'assumed' }]));
    expect(box.hidden).toBe(false);
    const chips = [...box.querySelectorAll('.legend-item')];
    // Сначала образцы колец статусов (fixture-узлы verified → ● в сети),
    // затем значки ролей с подписями типов, затем пунктирная строка
    // предполагаемой связи.
    const marks = chips.map((c) => (c as HTMLElement).dataset.status ?? null);
    expect(marks.filter((x) => x !== null)).toEqual(['online']);
    const kinds = chips.map((c) => (c as HTMLElement).dataset.kind);
    expect(kinds).toEqual([undefined, 'router', 'printer', 'assumed']);
    // Статусная строка — SVG-образец кольца (NR-036 п.2).
    const statusChip = chips.find((c) => (c as HTMLElement).dataset.status === 'online');
    const img = statusChip?.querySelector('img');
    expect(img?.getAttribute('src')).toContain('data:image/svg+xml');
    expect(statusChip?.textContent).toContain('в сети');
    // Строка роли — значок диска с белым глифом.
    const roleChip = chips.find((c) => (c as HTMLElement).dataset.kind === 'router');
    expect(decodeURIComponent(roleChip?.querySelector('img')?.getAttribute('src') ?? '')).toContain('#2F6FB5');
    // Пунктирная строка с текстом из наряда.
    const assumed = box.querySelector('.legend-assumed');
    expect(assumed?.textContent).toBe(ASSUMED_TEXT);
    expect(assumed?.querySelector('.legend-dash')).not.toBeNull();
  });

  it('без предполагаемых связей пунктирной строки нет', () => {
    const box = document.createElement('div');
    renderLegend(box, graph([{ kind: 'device' }], [{ source: 'fdb' }]));
    expect(box.querySelector('.legend-assumed')).toBeNull();
  });

  it('пустая карта скрывает легенду', () => {
    const box = document.createElement('div');
    renderLegend(box, graph([], []));
    expect(box.hidden).toBe(true);
  });
});
