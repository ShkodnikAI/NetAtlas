// Тесты форм узлов: значки различаются формой и подписью, метки
// «вручную» и «не проверен» выставляются.

import { describe, expect, it } from 'vitest';
import type { NodeInfo } from './api';
import { badges, nodeStyle, svgIcon } from './nodes';

function node(kind: string, manual = false, verified = true): NodeInfo {
  return { id: '00:00:00:00:00:01', kind, label: 'x', manual, verified };
}

describe('nodeStyle', () => {
  it('десять типов получают формы', () => {
    const kinds = [
      'internet', 'router', 'switch', 'ap', 'server',
      'device', 'laptop', 'printer', 'cloud', 'unknown',
    ];
    const shapes = new Set(kinds.map((k) => nodeStyle(node(k)).shape));
    expect(shapes.size).toBe(kinds.length);
  });

  it('у каждого типа есть иконка и подпись типа', () => {
    for (const kind of ['internet', 'router', 'switch', 'ap', 'server', 'device', 'laptop', 'printer', 'cloud', 'unknown']) {
      const st = nodeStyle(node(kind));
      expect(st.icon).toContain('data:image/svg+xml');
      expect(st.kindLabel).not.toBe('');
    }
  });

  it('неизвестный kind ведёт себя как unknown', () => {
    expect(nodeStyle(node('самозванец')).shape).toBe(nodeStyle(node('unknown')).shape);
  });

  it('svgIcon содержит путь иконки', () => {
    expect(svgIcon('switch')).toContain('%3Cpath');
  });
});

describe('badges', () => {
  it('ручной непроверенный элемент получает обе метки', () => {
    expect(badges(node('device', true, false))).toEqual(['вручную', 'не проверен']);
  });
  it('найденное проверенное — без меток', () => {
    expect(badges(node('device', false, true))).toEqual([]);
  });
});
