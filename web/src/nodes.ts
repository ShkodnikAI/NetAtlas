// Значки узлов карты (NR-036, вариант В «Цвет по роли»): круглый диск,
// цвет которого задаётся ролью устройства, белый глиф типа по центру,
// внешнее кольцо статуса и маркер формы в правом верхнем углу. Статус
// различается формой маркера, а не только цветом: ● в сети, ▲ внимание,
// ■ проблема, ○ не в сети, ◇ не проверен. Цвета ролей подобраны так,
// чтобы белый глиф читался с контрастом не ниже 4.5:1 (WCAG AA,
// проверяется юнит-тестом по таблице цветов).

import type { NodeInfo } from './api';

export interface NodeStyle {
  // cytoscape shape
  shape: string;
  // SVG-иконка узла (data URI для background-image)
  icon: string;
  // подпись типа под именем узла
  kindLabel: string;
  // цвет кольца статуса
  borderColor: string;
  width: number;
  height: number;
}

// Статусы узлов и их маркеры (NR-033 п.2, NR-036): цвет кольца,
// форма-символ (различение без цвета) и стиль линии кольца —
// «не в сети» и «не проверен» рисуются пунктиром.
export type NodeStatusKind = 'online' | 'attention' | 'problem' | 'offline' | 'unverified';

// STATUS_STYLES — цвет и стиль кольца статуса (NR-036): в сети,
// внимание и проблема — сплошные; не в сети (#9AA6B5) и не проверен
// (#5AA9FF) — пунктирные.
export const STATUS_STYLES: Record<
  NodeStatusKind,
  { color: string; glyph: string; label: string; dashed: boolean }
> = {
  online: { color: '#5FD38D', glyph: '●', label: 'в сети', dashed: false },
  attention: { color: '#F5B83D', glyph: '▲', label: 'внимание', dashed: false },
  problem: { color: '#FF7A7A', glyph: '■', label: 'проблема', dashed: false },
  offline: { color: '#9AA6B5', glyph: '○', label: 'не в сети', dashed: true },
  unverified: { color: '#5AA9FF', glyph: '◇', label: 'не проверен', dashed: true },
};

// Геометрия значка (NR-036): узел cytoscape — 80×80 (сетка 100×120),
// сам значок — 74 px: кольцо статуса толщиной 2 px с зазором 4 px до
// диска 62 px; глиф 34 px по центру диска; маркер формы — круг 22 px
// в правом верхнем углу. Кольцо рисуется внутри SVG (рамка узла
// cytoscape не используется), поэтому выделение узла — яркая внешняя
// обводка #E6EAF0 — не меняет цвет статуса.
export const BADGE_NODE = 80;
export const BADGE_SIZE = 74;
const CENTER = BADGE_NODE / 2;
const DISK_R = 31;
const GLYPH_SIZE = 34;
const MARKER_R = 11;
// Пунктир кольца «не в сети» и «не проверен» (NR-036).
const RING_DASH = '4 3';
// Центр маркера формы: на диагонали к правому верхнему углу, внешний
// край касается внутреннего края кольца (расстояние 17√2 ≈ 24.04,
// кольцо начинается на радиусе 35).
const MARKER_DX = 17;
const MARKER_DY = -17;

// ROLE_COLORS — цвет диска по роли (вариант В, NR-036). Группы:
// сеть (синий), серверы и хранилища (фиолетовый), компьютеры
// (зелёно-бирюзовый), периферия (коричневый), смартфоны/IoT/ТВ
// (малиновый), неизвестное (серый). Белый глиф на каждом цвете имеет
// контраст не ниже 4.5:1.
export const ROLE_COLORS: Record<string, string> = {
  router: '#2F6FB5',
  switch: '#2F6FB5',
  ap: '#2F6FB5',
  internet: '#2F6FB5',
  server: '#6A4FB3',
  nas: '#6A4FB3',
  device: '#2F7A68',
  laptop: '#2F7A68',
  printer: '#94591F',
  camera: '#94591F',
  phone: '#A13F72',
  iot: '#A13F72',
  tv: '#A13F72',
  unknown: '#4A5568',
  host: '#4A5568',
  cloud: '#4A5568',
};

// GLYPHS — глиф типа: два пути в viewBox 24×24 (тело и детали),
// рисуются белым, обводка 1.75, скругления round, без заливки.
export interface Glyph {
  body: string;
  d: string;
}

export const GLYPHS: Record<string, Glyph> = {
  router: {
    body: 'M3 14h18v6H3z',
    d: 'M7 17h.01M11 17h.01M8 14V9M16 14V9M8 9l-1-2M16 9l1-2',
  },
  switch: {
    body: 'M2.5 8h19v8h-19z',
    d: 'M6 12h.01M10 12h.01M14 12h.01M18 12h.01',
  },
  ap: {
    body: 'M10 18.5a2 2 0 1 0 4 0a2 2 0 1 0-4 0',
    d: 'M3 9a13 13 0 0 1 18 0M6 12.5a8.5 8.5 0 0 1 12 0M9 16a4 4 0 0 1 6 0',
  },
  internet: {
    body: 'M6.5 18h11a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.4 9.2 4.4 4.4 0 0 0 6.5 18z',
    d: 'M6.5 18h11',
  },
  server: {
    body: 'M3.5 4h17v6h-17zM3.5 14h17v6h-17z',
    d: 'M7 7h.01M7 17h.01M11 7h6M11 17h6',
  },
  nas: {
    body: 'M4 5h16v14H4z',
    d: 'M7 9h10M7 13h10M8 17h.01M12 17h.01',
  },
  device: {
    body: 'M3 4h18v12H3z',
    d: 'M9 20h6M12 16v4',
  },
  laptop: {
    body: 'M5 5h14v10H5z',
    d: 'M2.5 19h19M2.5 19l2.5-4M21.5 19L19 15',
  },
  printer: {
    body: 'M4 9h16v8H4z',
    d: 'M7 9V4h10v5M7 14h10v6H7z',
  },
  camera: {
    body: 'M4 9h16v8H4z',
    d: 'M12 11.5a2.5 2.5 0 1 0 0 5a2.5 2.5 0 1 0 0-5M8 9l1-2h6l1 2',
  },
  phone: {
    body: 'M7 2.5h10v19H7z',
    d: 'M11 18.5h2',
  },
  iot: {
    body: 'M7 7h10v10H7z',
    d: 'M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4',
  },
  tv: {
    body: 'M3 6h18v11H3z',
    d: 'M8 21h8M12 17v4',
  },
  // Неизвестное, хост без MAC и неуправляемый коммутатор делят
  // нейтральный серый диск и глиф «?» — роль не определена.
  unknown: {
    body: 'M4 4h16v16H4z',
    d: 'M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7M12 17h.01',
  },
  host: {
    body: 'M4 4h16v16H4z',
    d: 'M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7M12 17h.01',
  },
  cloud: {
    body: 'M4 4h16v16H4z',
    d: 'M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7M12 17h.01',
  },
};

// KIND_LABELS — подпись типа для панели и значков.
export const KIND_LABELS: Record<string, string> = {
  internet: 'интернет',
  router: 'роутер',
  switch: 'коммутатор',
  ap: 'точка доступа',
  server: 'сервер',
  device: 'компьютер',
  laptop: 'ноутбук',
  printer: 'принтер',
  // NR-032 п.5: новые типы классификатора.
  phone: 'телефон',
  iot: 'IoT-устройство',
  tv: 'телевизор',
  camera: 'камера',
  nas: 'NAS',
  cloud: 'неуправляемый коммутатор',
  unknown: 'неизвестное устройство',
  host: 'хост без MAC',
};

// svgIcon — data URI значка (NR-036): кольцо статуса (при заданном
// статусе), диск цвета роли, белый глиф типа, маркер формы в правом
// верхнем углу и счётчик открытых решений в левом нижнем.
// status undefined — значок роли без кольца и маркера (легенда,
// таблицы, панели, выбор типа — кольца статусов показываются отдельно).
export function svgIcon(kind: string, status?: NodeStatusKind, decisions = 0): string {
  const known = Object.prototype.hasOwnProperty.call(GLYPHS, kind);
  const k = known ? kind : 'unknown';
  const disk = ROLE_COLORS[k] ?? ROLE_COLORS['unknown'] ?? '#4A5568';
  const glyph: Glyph = GLYPHS[k] ?? { body: '', d: '' };
  let inner = '';
  if (status !== undefined) {
    // Кольцо статуса: 2 px на радиусе 36 (занимает 35–37), зазор 4 px
    // до диска 62 px; «не в сети» и «не проверен» — пунктир.
    const dash = STATUS_STYLES[status].dashed ? ` stroke-dasharray="${RING_DASH}"` : '';
    inner +=
      `<circle cx="${CENTER}" cy="${CENTER}" r="36" fill="none" ` +
      `stroke="${STATUS_STYLES[status].color}" stroke-width="2"${dash}/>`;
  }
  inner +=
    `<circle cx="${CENTER}" cy="${CENTER}" r="${DISK_R}" fill="${disk}" stroke="none"/>` +
    glyphWhite(glyph);
  if (status !== undefined) {
    inner += statusMarker(status);
    if (decisions > 0) inner += decisionBadge(decisions);
  }
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="${BADGE_NODE}" height="${BADGE_NODE}" ` +
    `viewBox="0 0 ${BADGE_NODE} ${BADGE_NODE}">${inner}</svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

// glyphWhite — глиф типа: вложенный SVG 34×34 с viewBox 24×24, белый,
// обводка 1.75, скругления round, без заливки; два пути (тело, детали).
function glyphWhite(g: Glyph): string {
  const half = GLYPH_SIZE / 2;
  const x = CENTER - half;
  return (
    `<svg x="${x}" y="${x}" width="${GLYPH_SIZE}" height="${GLYPH_SIZE}" viewBox="0 0 24 24" ` +
    `fill="none" stroke="#FFFFFF" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">` +
    `<path d="${g.body}"/><path d="${g.d}"/></svg>`
  );
}

// statusMarker — маркер статуса в правом верхнем углу значка: круг
// 22 px на фоне #0E1116 с обводкой 1 px цвета статуса и символом
// формы (● ▲ ■ ○ ◇) того же цвета — статус различим без цвета.
function statusMarker(status: NodeStatusKind): string {
  const c = STATUS_STYLES[status].color;
  const halo =
    `<circle cx="${CENTER + MARKER_DX}" cy="${CENTER + MARKER_DY}" r="${MARKER_R}" ` +
    `fill="#0E1116" stroke="${c}" stroke-width="1"/>`;
  return halo + shapeSymbol(status, CENTER + MARKER_DX, CENTER + MARKER_DY, 1);
}

// shapeSymbol — символ формы статуса: ● ▲ ■ ○ ◇ (заливка или контур),
// координаты масштабируются коэффициентом k от центра (cx, cy).
function shapeSymbol(status: NodeStatusKind, cx: number, cy: number, k: number): string {
  const c = STATUS_STYLES[status].color;
  const n = (v: number): string => String(Math.round(v * 1000) / 1000);
  switch (status) {
    case 'online':
      return `<circle cx="${n(cx)}" cy="${n(cy)}" r="${n(4.5 * k)}" fill="${c}" stroke="none"/>`;
    case 'attention':
      return (
        `<path d="M${n(cx)} ${n(cy - 4.6 * k)}L${n(cx + 4.6 * k)} ${n(cy + 3.4 * k)}` +
        `H${n(cx - 4.6 * k)}Z" fill="${c}" stroke="none"/>`
      );
    case 'problem':
      return (
        `<rect x="${n(cx - 4.2 * k)}" y="${n(cy - 4.2 * k)}" ` +
        `width="${n(8.4 * k)}" height="${n(8.4 * k)}" fill="${c}" stroke="none"/>`
      );
    case 'offline':
      return (
        `<circle cx="${n(cx)}" cy="${n(cy)}" r="${n(4.2 * k)}" fill="none" ` +
        `stroke="${c}" stroke-width="${n(1.7 * k)}"/>`
      );
    case 'unverified':
      return (
        `<path d="M${n(cx)} ${n(cy - 5.4 * k)}L${n(cx + 4.8 * k)} ${n(cy)}` +
        `L${n(cx)} ${n(cy + 5.4 * k)}L${n(cx - 4.8 * k)} ${n(cy)}Z" ` +
        `fill="none" stroke="${c}" stroke-width="${n(1.7 * k)}"/>`
      );
    default:
      return '';
  }
}

// statusSample — образец кольца статуса для легенды (NR-036 п.2):
// окружность цвета статуса (сплошная или пунктирная) с символом формы
// в центре; значок роли показывается отдельно.
export function statusSample(status: NodeStatusKind): string {
  const s = STATUS_STYLES[status];
  const dash = s.dashed ? ' stroke-dasharray="3.5 2.5"' : '';
  const ring = `<circle cx="11" cy="11" r="8.5" fill="none" stroke="${s.color}" stroke-width="2"${dash}/>`;
  const sym = shapeSymbol(status, 11, 11, 0.62);
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 22 22">${ring}${sym}</svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

// decisionBadge — счётчик открытых решений в левом нижнем углу диска:
// жёлтый кружок с тёмным числом (контраст #0E1116 на #F5B83D).
function decisionBadge(count: number): string {
  const label = count > 9 ? '9+' : String(count);
  const cx = CENTER - 16;
  const cy = CENTER + 16;
  return (
    `<circle cx="${cx}" cy="${cy}" r="8" fill="#F5B83D" stroke="#0E1116" stroke-width="0.8"/>` +
    `<text x="${cx}" y="${cy + 3.7}" font-size="10.5" font-family="system-ui, sans-serif"` +
    ` font-weight="700" fill="#0E1116" text-anchor="middle" stroke="none">${label}</text>`
  );
}

// nodeStyle — значок и подпись типа для узла графа (NR-036): все типы
// рисуются круглым диском 74 px в узле 80×80; цвет кольца статуса
// возвращается в borderColor (данные узла), тип выводится из kind,
// статус — из сигналов (NR-033).
export function nodeStyle(n: NodeInfo, status: NodeStatusKind = 'online', decisions = 0): NodeStyle {
  const known = Object.prototype.hasOwnProperty.call(ROLE_COLORS, n.kind);
  const kind = known ? n.kind : 'unknown';
  const st = STATUS_STYLES[status] ?? STATUS_STYLES['online'];
  return {
    shape: 'ellipse',
    icon: svgIcon(kind, status, decisions),
    kindLabel: KIND_LABELS[kind] ?? KIND_LABELS['unknown'] ?? 'неизвестное устройство',
    borderColor: st.color,
    width: BADGE_NODE,
    height: BADGE_NODE,
  };
}

// badges — метки элемента: «вручную» и «не проверен».
export function badges(n: NodeInfo): string[] {
  const out: string[] = [];
  if (n.manual) out.push('вручную');
  if (!n.verified) out.push('не проверен');
  return out;
}
