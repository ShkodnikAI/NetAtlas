// Тесты значков (NR-036, вариант В «Цвет по роли»): каждому виду из
// internal/model и ручных типов соответствует запись таблицы (цвет
// диска, глиф, подпись); белый глиф читается на диске с контрастом
// не ниже 4.5:1; статусы различаются формой маркера и цветом кольца,
// «не в сети» и «не проверен» — пунктирные.

import { describe, expect, it } from 'vitest';
import type { NodeInfo } from './api';
import {
  GLYPHS,
  KIND_LABELS,
  ROLE_COLORS,
  STATUS_STYLES,
  badges,
  nodeStyle,
  statusSample,
  svgIcon,
} from './nodes';

function node(kind: string, manual = false, verified = true): NodeInfo {
  return { id: '00:00:00:00:00:01', kind, label: 'x', manual, verified };
}

const decode = (uri: string): string => decodeURIComponent(uri);

// MODEL_KINDS — виды узлов из internal/model/topology.go (константы
// NodeKind*): таблица значков обязана покрывать их все (NR-036 п.5).
// MANUAL_KINDS — типы, добавляемые вручную/классификатором вне
// текущих констант модели (значки готовы заранее, NR-033).
const MODEL_KINDS = [
  'device',
  'switch',
  'cloud',
  'internet',
  'router',
  'ap',
  'server',
  'laptop',
  'printer',
  'unknown',
  'host',
  'phone',
  'iot',
  'tv',
];
const MANUAL_KINDS = ['nas', 'camera'];

// luminance — относительная яркость цвета #RRGGBB (WCAG 2.x).
function luminance(hex: string): number {
  const v = hex.replace('#', '');
  const lin = (c: number): number => (c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4));
  const r = lin(parseInt(v.slice(0, 2), 16) / 255);
  const g = lin(parseInt(v.slice(2, 4), 16) / 255);
  const b = lin(parseInt(v.slice(4, 6), 16) / 255);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

// contrast — контраст двух цветов по WCAG.
function contrast(a: string, b: string): number {
  const la = luminance(a);
  const lb = luminance(b);
  const hi = Math.max(la, lb);
  const lo = Math.min(la, lb);
  return (hi + 0.05) / (lo + 0.05);
}

describe('таблица ролей (NR-036)', () => {
  it('каждому виду из internal/model и ручных типов соответствует запись', () => {
    const kinds = [...new Set([...MODEL_KINDS, ...MANUAL_KINDS])];
    expect(kinds.length).toBe(16);
    for (const kind of kinds) {
      expect(ROLE_COLORS[kind], `цвет диска ${kind}`).toMatch(/^#[0-9A-Fa-f]{6}$/);
      const glyph = GLYPHS[kind];
      expect(glyph, `глиф ${kind}`).toBeDefined();
      expect(glyph?.body, `тело глифа ${kind}`).not.toBe('');
      expect(glyph?.d, `детали глифа ${kind}`).not.toBe('');
      expect(KIND_LABELS[kind], `подпись ${kind}`).not.toBe('');
    }
  });

  it('белый глиф на диске каждой роли — контраст не ниже 4.5:1', () => {
    const colors = [...new Set(Object.values(ROLE_COLORS))];
    for (const color of colors) {
      expect(contrast('#FFFFFF', color)).toBeGreaterThanOrEqual(4.5);
    }
  });

  it('группы ролей делят цвета: сеть, серверы, компьютеры, периферия, мобильное, прочее', () => {
    expect(ROLE_COLORS['router']).toBe(ROLE_COLORS['switch']);
    expect(ROLE_COLORS['switch']).toBe(ROLE_COLORS['ap']);
    expect(ROLE_COLORS['ap']).toBe(ROLE_COLORS['internet']);
    expect(ROLE_COLORS['server']).toBe(ROLE_COLORS['nas']);
    expect(ROLE_COLORS['device']).toBe(ROLE_COLORS['laptop']);
    expect(ROLE_COLORS['printer']).toBe(ROLE_COLORS['camera']);
    expect(ROLE_COLORS['phone']).toBe(ROLE_COLORS['iot']);
    expect(ROLE_COLORS['iot']).toBe(ROLE_COLORS['tv']);
    expect(ROLE_COLORS['unknown']).toBe(ROLE_COLORS['host']);
    expect(ROLE_COLORS['host']).toBe(ROLE_COLORS['cloud']);
    const groups = new Set(Object.values(ROLE_COLORS));
    expect(groups.size).toBe(6);
  });
});

describe('nodeStyle', () => {
  it('все типы рисуются круглым диском 80×80 и получают отдельные значки', () => {
    const kinds = [...new Set([...MODEL_KINDS, ...MANUAL_KINDS])];
    const icons = kinds.map((k) => nodeStyle(node(k)).icon);
    // unknown/host/cloud делят один значок — общая роль «неизвестное»
    // (NR-036: один цвет #4A5568 и один глиф «?» на троих).
    expect(new Set(icons).size).toBe(kinds.length - 2);
    expect(nodeStyle(node('host')).icon).toBe(nodeStyle(node('unknown')).icon);
    expect(nodeStyle(node('cloud')).icon).toBe(nodeStyle(node('unknown')).icon);
    for (const kind of kinds) {
      const st = nodeStyle(node(kind));
      expect(st.shape).toBe('ellipse');
      expect(st.width).toBe(80);
      expect(st.height).toBe(80);
      expect(st.kindLabel).not.toBe('');
      expect(st.icon).toContain('data:image/svg+xml');
    }
  });

  it('значок роли: диск цвета роли и белый глиф, без кольца и маркера', () => {
    const svg = decode(svgIcon('router'));
    expect(svg).toContain('#2F6FB5');
    expect(svg).toContain('stroke="#FFFFFF"');
    expect(svg).toContain('stroke-width="1.75"');
    // Кольца статуса и маркера нет, пока статус не задан.
    expect(svg).not.toContain('r="36"');
    expect(svg).not.toContain('#0E1116');
  });

  it('кольцо статуса в значке: 2 px на радиусе 36, цвет по статусу', () => {
    const svg = decode(nodeStyle(node('router'), 'online').icon);
    expect(svg).toContain('<circle cx="40" cy="40" r="36" fill="none" stroke="#5FD38D" stroke-width="2"/>');
    // Зазор 4 px: внутренний край кольца (35) — край диска (31).
    expect(svg).toContain('r="31"');
  });

  it('кольца «не в сети» и «не проверен» пунктирные (различимы без цвета)', () => {
    expect(decode(nodeStyle(node('router'), 'offline').icon)).toContain('stroke-dasharray="4 3"');
    expect(decode(nodeStyle(node('router'), 'unverified').icon)).toContain('stroke-dasharray="4 3"');
    expect(decode(nodeStyle(node('router'), 'online').icon)).not.toContain('stroke-dasharray');
    expect(decode(nodeStyle(node('router'), 'attention').icon)).not.toContain('stroke-dasharray');
    expect(decode(nodeStyle(node('router'), 'problem').icon)).not.toContain('stroke-dasharray');
  });

  it('неизвестный kind ведёт себя как unknown', () => {
    expect(nodeStyle(node('самозванец')).icon).toBe(nodeStyle(node('unknown')).icon);
    expect(nodeStyle(node('самозванец')).kindLabel).toBe('неизвестное устройство');
  });
});

describe('статусы (NR-036)', () => {
  it('пять статусов дают разные значки и цвет кольца по статусу', () => {
    const kinds = ['online', 'attention', 'problem', 'offline', 'unverified'] as const;
    const icons = kinds.map((s) => nodeStyle(node('router'), s).icon);
    expect(new Set(icons).size).toBe(kinds.length);
    for (const s of kinds) {
      expect(nodeStyle(node('router'), s).borderColor).toBe(STATUS_STYLES[s].color);
    }
  });

  it('кольцо: «не в сети» и «не проверен» пунктирные, остальные сплошные', () => {
    expect(STATUS_STYLES.offline.dashed).toBe(true);
    expect(STATUS_STYLES.unverified.dashed).toBe(true);
    expect(STATUS_STYLES.online.dashed).toBe(false);
    expect(STATUS_STYLES.attention.dashed).toBe(false);
    expect(STATUS_STYLES.problem.dashed).toBe(false);
  });

  it('маркер формы в правом верхнем углу: тёмный круг с обводкой статуса', () => {
    for (const s of ['online', 'attention', 'problem', 'offline', 'unverified'] as const) {
      const svg = decode(nodeStyle(node('router'), s).icon);
      // Диск маркера на фоне #0E1116 с обводкой цвета статуса.
      expect(svg).toContain('fill="#0E1116"');
      expect(svg).toContain(STATUS_STYLES[s].color);
    }
  });

  it('формы маркеров различаются: у каждого статуса свой символ', () => {
    // Символ идёт сразу после круга-подложки маркера; сами SVG-фрагменты
    // символов у пяти статусов различны (форма различает без цвета).
    const frags = ['online', 'attention', 'problem', 'offline', 'unverified'].map((s) => {
      const svg = decode(nodeStyle(node('router'), s as never).icon);
      const idx = svg.indexOf('stroke-width="1"/>');
      expect(idx, `маркер ${s}`).toBeGreaterThan(-1);
      return svg.slice(idx + 'stroke-width="1"/>'.length).replace('</svg>', '');
    });
    expect(new Set(frags).size).toBe(5);
  });

  it('счётчик решений рисуется на значке и не рисуется при нуле', () => {
    const withCounter = decode(nodeStyle(node('router'), 'attention', 3).icon);
    const withoutCounter = decode(nodeStyle(node('router'), 'attention', 0).icon);
    expect(withCounter).toContain('>3<');
    expect(withCounter).toContain('#F5B83D');
    expect(withoutCounter).not.toContain('>3<');
  });
});

describe('образцы колец статусов для легенды (NR-036 п.2)', () => {
  it('пунктирные статусы дают stroke-dasharray, сплошные — нет', () => {
    expect(decode(statusSample('offline'))).toContain('stroke-dasharray');
    expect(decode(statusSample('unverified'))).toContain('stroke-dasharray');
    expect(decode(statusSample('online'))).not.toContain('stroke-dasharray');
    expect(decode(statusSample('attention'))).not.toContain('stroke-dasharray');
    expect(decode(statusSample('problem'))).not.toContain('stroke-dasharray');
  });

  it('образец окрашен цветом статуса и несёт символ формы', () => {
    const svg = decode(statusSample('problem'));
    expect(svg).toContain('#FF7A7A');
    expect(svg).toContain('<rect');
    expect(svg).toContain('data:image/svg+xml');
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
