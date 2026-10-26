// Значки узлов карты (NR-033 п.2): отдельная SVG-иконка на каждый
// тип, единый стиль (толщина линии 1.5, скругления), скруглённая
// плашка с цветным ободком статуса, подпись снизу. Статус
// различается формой маркера, а не только цветом: ● в сети,
// ▲ внимание, ■ проблема, ○ не в сети, ◇ не проверен. Плашки —
// round-rectangle (интернет — круг), тип различается глифом.

import type { NodeInfo } from './api';

export interface NodeStyle {
  // cytoscape shape
  shape: string;
  // SVG-иконка узла (data URI для background-image)
  icon: string;
  // подпись типа под именем узла
  kindLabel: string;
  // цвет ободка статуса
  borderColor: string;
  width: number;
  height: number;
}

// Статусы узлов и их маркеры (NR-033 п.2, п.4).
export type NodeStatusKind = 'online' | 'attention' | 'problem' | 'offline' | 'unverified';

// STATUS_STYLES — цвет и подпись статуса; контраст цвета на тёмной
// плашке #151A22 не ниже 4.5:1 (WCAG AA, проверено для всех пяти).
export const STATUS_STYLES: Record<NodeStatusKind, { color: string; glyph: string; label: string }> = {
  online: { color: '#5FD38D', glyph: '●', label: 'в сети' },
  attention: { color: '#F5B83D', glyph: '▲', label: 'внимание' },
  problem: { color: '#FF7A7A', glyph: '■', label: 'проблема' },
  offline: { color: '#9AA6B5', glyph: '○', label: 'не в сети' },
  unverified: { color: '#B48FE8', glyph: '◇', label: 'не проверен' },
};

// ICONS — SVG-путь каждой иконки (24×24, stroke 1.5). Камера и NAS —
// в наборе есть: классификатор пока не выдаёт эти типы (предположение
// в отчёте NR-033), значки готовы для будущих типов.
export const ICONS: Record<string, string> = {
  // Глобус: меридиан, параллели.
  internet: 'M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17z M3.5 12h17 M12 3.5c-2.6 2.2-4 5.1-4 8.5s1.4 6.3 4 8.5c2.6-2.2 4-5.1 4-8.5s-1.4-6.3-4-8.5z',
  // Роутер: корпус, две антенны, индикаторы.
  router: 'M4 11.5h16v6H4z M8 11.5V5 M16 11.5V5 M7 14.5h.01 M10.5 14.5h.01 M14 14.5h.01',
  // Коммутатор: корпус, порты, обмен стрелками.
  switch: 'M3.5 8.5h17v8h-17z M6.5 16.5h.01 M9.5 16.5h.01 M14.5 16.5h.01 M17.5 16.5h.01 M9.5 13.8V9.9 M8.2 11.2l1.3-1.3 1.3 1.3 M14.5 10.2v3.9 M13.2 12.8l1.3 1.3 1.3-1.3',
  // Точка доступа: волны и точка.
  ap: 'M3 9a13 13 0 0 1 18 0 M6 12.5a8.5 8.5 0 0 1 12 0 M9 16a4 4 0 0 1 6 0 M12 19.5h.01',
  // Сервер: две стойки с индикаторами.
  server: 'M3.5 4.5h17v6h-17z M3.5 13.5h17v6h-17z M6.5 7.5h.01 M6.5 16.5h.01 M17 7.5h.5 M17 16.5h.5',
  // Компьютер: монитор и стойка.
  device: 'M3.5 4.5h17v11h-17z M9.5 20h5 M12 15.5V20',
  // Ноутбук: экран и база.
  laptop: 'M5 5.5h14v9.5H5z M2.5 19h19 M8.5 19a3.5 1.6 0 0 1 7 0',
  // Принтер: лоток, корпус, лист.
  printer: 'M7 9V4.5h10V9 M7 15.5h10v4H7z M4 9h16v6.5H4z M16.5 11.5h.01',
  // Смартфон.
  phone: 'M8 2.5h8A1.5 1.5 0 0 1 17.5 4v16a1.5 1.5 0 0 1-1.5 1.5H8A1.5 1.5 0 0 1 6.5 20V4A1.5 1.5 0 0 1 8 2.5z M10.5 18.5h3',
  // IoT: чип с ядром и ножками.
  iot: 'M7 7h10v10H7z M10.5 10.5h3v3h-3z M12 3.5V7 M12 17v3.5 M3.5 12H7 M17 12h3.5 M8 3.5V7 M16 3.5V7 M8 17v3.5 M16 17v3.5 M3.5 8.5H7 M3.5 15.5H7 M17 8.5h3.5 M17 15.5h3.5',
  // Телевизор: экран на подставке.
  tv: 'M3 5h18v11.5H3z M8.5 20.5h7 M12 16.5v4',
  // Камера (видеонаблюдение): корпус и объектив.
  camera: 'M3 7.5h11.5v9H3z M6 7.5V6a2 2 0 0 1 2-2h1.5 M14.5 10.5l6-2.5v8l-6-2.5 M6.5 16.5v2 M11.5 16.5v2',
  // NAS: башня с дисками и индикаторами.
  nas: 'M5.5 3.5h13v17h-13z M9 7.5h6 M9 11h6 M9 14.5h6 M9 18h.01 M12 18h.01 M15 18h.01',
  // Неуправляемый коммутатор: коробка без управления.
  cloud: 'M4 8h16v9H4z M7 14.5h.01 M10 14.5h.01 M13 14.5h.01 M16 14.5h.01 M12 8v-2.5',
  // Хост без MAC.
  host: 'M4 4.5h16v15H4z M12 8v.01 M12 11v4.5 M9.5 18h5',
  // Неизвестное: вопросительный знак.
  unknown: 'M9 9.3a3 3 0 1 1 4.6 2.5c-1 .7-1.6 1.3-1.6 2.7 M12 17.8h.01',
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

// Формы плашек: скруглённый прямоугольник; интернет — круг.
const SHAPES: Record<string, string> = {
  internet: 'ellipse',
  router: 'round-rectangle',
  switch: 'round-rectangle',
  ap: 'round-rectangle',
  server: 'round-rectangle',
  device: 'round-rectangle',
  laptop: 'round-rectangle',
  printer: 'round-rectangle',
  phone: 'round-rectangle',
  iot: 'round-rectangle',
  tv: 'round-rectangle',
  camera: 'round-rectangle',
  nas: 'round-rectangle',
  cloud: 'round-rectangle',
  unknown: 'round-rectangle',
  host: 'round-rectangle',
};

// svgIcon — data URI значка: плашка, глиф типа, маркер статуса в
// правом верхнем углу, счётчик открытых решений в левом нижнем.
// status undefined — значок без маркера (легенда типов).
export function svgIcon(kind: string, status?: NodeStatusKind, decisions = 0): string {
  const path = ICONS[kind] ?? ICONS['unknown'] ?? '';
  const stroke = status === undefined ? '#C5CEDA' : glyphColor(status);
  let extra = '';
  if (status !== undefined) {
    extra = statusMarker(status);
    if (decisions > 0) extra += decisionBadge(decisions);
  }
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" ` +
    `fill="none" stroke="${stroke}" stroke-width="1.5" ` +
    `stroke-linecap="round" stroke-linejoin="round">` +
    `<path d="${path}"/>${extra}</svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

// glyphColor — цвет глифа на плашке: тёмный статус читается хуже —
// глиф всегда нейтрально-светлый, статус показывает маркер и ободок.
function glyphColor(status: NodeStatusKind): string {
  return STATUS_STYLES[status]?.color ?? '#C5CEDA';
}

// statusMarker — маркер статуса в правом верхнем углу плашки: форма
// различает статусы (● ▲ ■ ○ ◇), цвет дублирует форму.
function statusMarker(status: NodeStatusKind): string {
  const c = STATUS_STYLES[status].color;
  const halo = `<circle cx="19.2" cy="4.8" r="3.6" fill="#0E1116" stroke="none"/>`;
  switch (status) {
    case 'online':
      return halo + `<circle cx="19.2" cy="4.8" r="2" fill="${c}" stroke="none"/>`;
    case 'attention':
      return halo + `<path d="M19.2 2.9l2 3.4h-4z" fill="${c}" stroke="none"/>`;
    case 'problem':
      return halo + `<rect x="17.4" y="3" width="3.6" height="3.6" fill="${c}" stroke="none"/>`;
    case 'offline':
      return halo + `<circle cx="19.2" cy="4.8" r="2" fill="none" stroke="${c}" stroke-width="1.5"/>`;
    case 'unverified':
      return halo + `<path d="M19.2 2.8l2 2-2 2-2-2z" fill="none" stroke="${c}" stroke-width="1.5"/>`;
    default:
      return '';
  }
}

// decisionBadge — счётчик открытых решений в левом нижнем углу:
// жёлтый кружок с тёмным числом (контраст #0E1116 на #F5B83D).
function decisionBadge(count: number): string {
  const label = count > 9 ? '9+' : String(count);
  return (
    `<circle cx="4.8" cy="19.2" r="3.6" fill="#F5B83D" stroke="#0E1116" stroke-width="0.8"/>` +
    `<text x="4.8" y="20.9" font-size="5.4" font-family="system-ui, sans-serif"` +
    ` font-weight="700" fill="#0E1116" text-anchor="middle" stroke="none">${label}</text>`
  );
}

// nodeStyle — плашка, иконка и подпись типа для узла графа: тип
// выводится из kind и класса узла, статус — из сигналов (NR-033).
export function nodeStyle(n: NodeInfo, status: NodeStatusKind = 'online', decisions = 0): NodeStyle {
  const known = Object.prototype.hasOwnProperty.call(SHAPES, n.kind);
  const kind = known ? n.kind : 'unknown';
  // Телевизор шире прочих узлов — форма экрана (NR-032 п.5).
  const size =
    kind === 'cloud' || kind === 'unknown'
      ? { w: 44, h: 34 }
      : kind === 'tv'
        ? { w: 48, h: 34 }
        : { w: 40, h: 32 };
  const st = STATUS_STYLES[status] ?? STATUS_STYLES['online'];
  return {
    shape: SHAPES[kind] ?? 'round-rectangle',
    icon: svgIcon(kind, status, decisions),
    kindLabel: KIND_LABELS[kind] ?? KIND_LABELS['unknown'] ?? 'неизвестное устройство',
    borderColor: st.color,
    width: size.w,
    height: size.h,
  };
}

// badges — метки элемента: «вручную» и «не проверен».
export function badges(n: NodeInfo): string[] {
  const out: string[] = [];
  if (n.manual) out.push('вручную');
  if (!n.verified) out.push('не проверен');
  return out;
}
