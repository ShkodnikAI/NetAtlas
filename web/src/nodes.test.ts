// Тесты форм узлов: значки различаются формой и подписью, метки
// «вручную» и «не проверен» выставляются.

import { describe, expect, it } from 'vitest';
import type { NodeInfo } from './api';
import { badges, nodeStyle, svgIcon } from './nodes';

function node(kind: string, manual = false, verified = true): NodeInfo {
  return { id: '00:00:00:00:00:01', kind, label: 'x', manual, verified };
}

describe('nodeStyle', () => {
  // NR-033 п.2: единая плашка у всех типов, тип различается
  // отдельной SVG-иконкой (глифом), а не формой узла.
  it('десять типов получают отдельные иконки-глифы', () => {
    const kinds = [
      'internet', 'router', 'switch', 'ap', 'server',
      'device', 'laptop', 'printer', 'cloud', 'unknown',
    ];
    const icons = new Set(kinds.map((k) => nodeStyle(node(k)).icon));
    expect(icons.size).toBe(kinds.length);
  });

  it('маркер статуса различается формой и цветом (NR-033 п.2)', () => {
    const kinds = ['online', 'attention', 'problem', 'offline', 'unverified'] as const;
    const icons = kinds.map((s) => nodeStyle(node('router'), s).icon);
    expect(new Set(icons).size).toBe(kinds.length);
    // Цвет ободка повторяет статус.
    const borders = new Set(kinds.map((s) => nodeStyle(node('router'), s).borderColor));
    expect(borders.size).toBe(kinds.length);
  });

  it('счётчик решений рисуется на значке и не рисуется при нуле', () => {
    const withCounter = nodeStyle(node('router'), 'attention', 3).icon;
    const withoutCounter = nodeStyle(node('router'), 'attention', 0).icon;
    expect(decodeURIComponent(withCounter)).toContain('>3<');
    expect(decodeURIComponent(withoutCounter)).not.toContain('>3<');
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

  it('хост без MAC получает форму, иконку и подпись (NR-023)', () => {
    const st = nodeStyle(node('host'));
    expect(st.icon).toContain('data:image/svg+xml');
    expect(st.kindLabel).toBe('хост без MAC');
    expect(st.shape).not.toBe('ellipse');
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
