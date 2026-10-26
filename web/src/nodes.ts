// Формы и подписи узлов карты: значки различаются формой и подписью,
// не только цветом (NR-022). Иконки — пути из design/Main.dc.html.

import type { NodeInfo } from './api';

export interface NodeStyle {
  // cytoscape shape
  shape: string;
  // SVG-иконка узла (data URI для background-image)
  icon: string;
  // подпись типа под именем узла
  kindLabel: string;
  width: number;
  height: number;
}

// ICONS — SVG-путь каждой иконки (24×24, stroke).
export const ICONS: Record<string, string> = {
  internet: 'M6.5 18h11a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.4 9.2 4.4 4.4 0 0 0 6.5 18z',
  router: 'M7 16.5h.01M11 16.5h.01M8 13V8M16 13V8 M3 13h18v7H3z',
  switch: 'M6 12h.01M10 12h.01M14 12h.01M18 12h.01 M2.5 8h19v8h-19z',
  ap: 'M3 9a13 13 0 0 1 18 0M6 12.5a8.5 8.5 0 0 1 12 0M9 16a4 4 0 0 1 6 0M12 19.5h.01',
  server: 'M7 7h.01M7 17h.01 M3.5 4h17v6h-17z M3.5 14h17v6h-17z',
  device: 'M9 20h6M12 16v4 M3 4h18v12H3z',
  laptop: 'M2.5 19h19 M5 5h14v10H5z',
  printer: 'M7 9V4h10v5 M7 14h10v6H7z M4 9h16v8H4z',
  // NR-032 п.5: смартфон, чип IoT и телевизор.
  phone: 'M8 2.5h8A1.5 1.5 0 0 1 17.5 4v16a1.5 1.5 0 0 1-1.5 1.5H8A1.5 1.5 0 0 1 6.5 20V4A1.5 1.5 0 0 1 8 2.5z M10.5 18.5h3',
  iot: 'M7 7h10v10H7z M10 10h4v4h-4z M12 3.5V7 M12 17v3.5 M3.5 12H7 M17 12h3.5 M8 3.5V7 M16 3.5V7 M8 17v3.5 M16 17v3.5 M3.5 8H7 M3.5 16H7 M17 8h3.5 M17 16h3.5',
  tv: 'M3 5h18v12H3z M8.5 21h7 M12 17v4',
  cloud: 'M9 12h6 M5 5h14v14H5z',
  unknown: 'M9 12h6 M5 5h14v14H5z',
  host: 'M12 7v.01M12 10v5 M4 4h16v16H4z',
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
  cloud: 'неуправляемый коммутатор',
  unknown: 'неизвестное устройство',
  host: 'хост без MAC',
};

// Формы cytoscape: у каждого типа своя фигура.
const SHAPES: Record<string, string> = {
  internet: 'octagon',
  router: 'hexagon',
  switch: 'cut-rectangle',
  ap: 'round-tag',
  server: 'bottom-round-rectangle',
  device: 'round-rectangle',
  laptop: 'rhomboid',
  printer: 'concave-hexagon',
  // NR-032 п.5: форма нового типа отличима на карте.
  phone: 'barrel',
  iot: 'diamond',
  tv: 'round-rectangle',
  cloud: 'tag',
  unknown: 'ellipse',
  host: 'round-rectangle',
};

// svgIcon — data URI с иконкой: рисуется внутри узла.
export function svgIcon(kind: string, color = '#C5CEDA'): string {
  const path = ICONS[kind] ?? ICONS['unknown'] ?? '';
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" ` +
    `fill="none" stroke="${color}" stroke-width="1.7" ` +
    `stroke-linecap="round" stroke-linejoin="round">` +
    `<path d="${path}"/></svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

// nodeStyle — форма, иконка и подпись типа для узла графа: тип
// выводится из kind и класса узла (найденное сканером — kind из
// сканера; ручное — выбранный при добавлении тип).
export function nodeStyle(n: NodeInfo): NodeStyle {
  const known = Object.prototype.hasOwnProperty.call(SHAPES, n.kind);
  const kind = known ? n.kind : 'unknown';
  // Телевизор шире прочих узлов — форма экрана (NR-032 п.5).
  const size =
    kind === 'cloud' || kind === 'unknown'
      ? { w: 44, h: 34 }
      : kind === 'tv'
        ? { w: 48, h: 34 }
        : { w: 40, h: 32 };
  return {
    shape: SHAPES[kind] ?? 'ellipse',
    icon: svgIcon(kind),
    kindLabel: KIND_LABELS[kind] ?? KIND_LABELS['unknown'] ?? 'неизвестное устройство',
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
