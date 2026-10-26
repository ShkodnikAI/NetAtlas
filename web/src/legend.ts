// Легенда карты (NR-032 п.3, п.5): внизу показываются типы узлов,
// которые есть на карте (значок + подпись), и — если на карте есть
// предполагаемые связи — пунктирная строка «предполагаемая связь:
// данных о коммутаторе нет». Функции чистые: legendItems вычисляет
// состав легенды, renderLegend рисует её в DOM (только textContent,
// данные API недоверенные).

import type { Graph } from './api';
import { KIND_LABELS, STATUS_STYLES, svgIcon, type NodeStatusKind } from './nodes';
import type { GraphStatuses } from './graph';

// StatusLegendItem — строка статуса: маркер (● ▲ ■ ○ ◇) и подпись.
export interface StatusLegendItem {
  status: NodeStatusKind;
  glyph: string;
  label: string;
}

// presentStatuses — статусы, реально присутствующие на карте
// (NR-033 п.5): порядок ■ ▲ ○ ◇ ● (по убыванию важности).
export function presentStatuses(
  g: Graph,
  statuses?: GraphStatuses,
): StatusLegendItem[] {
  const order: NodeStatusKind[] = ['problem', 'attention', 'offline', 'unverified', 'online'];
  const present = new Set<NodeStatusKind>();
  for (const n of g.nodes) {
    const raw = statuses?.status(n.id).status ?? 'online';
    const status: NodeStatusKind = raw === 'online' && !n.verified ? 'unverified' : raw;
    present.add(status);
  }
  return order
    .filter((s) => present.has(s))
    .map((s) => ({
      status: s,
      glyph: STATUS_STYLES[s].glyph,
      label: STATUS_STYLES[s].label,
    }));
}

// hasManualLinks — есть ли на карте ручные (пунктирные) связи.
export function hasManualLinks(g: Graph): boolean {
  return g.links.some((l) => l.manual);
}

// MANUAL_TEXT — подпись пунктирной строки ручной связи.
export const MANUAL_TEXT = 'ручная связь (пунктир)';

// Порядок типов в легенде: как в наряде — роутеры и коммутаторы,
// серверы, компьютеры, принтеры, телефоны, прочее.
const KIND_ORDER: string[] = [
  'internet',
  'router',
  'switch',
  'ap',
  'server',
  'device',
  'laptop',
  'printer',
  'phone',
  'iot',
  'tv',
  'cloud',
  'host',
  'unknown',
];

// ASSUMED_TEXT — подпись пунктирной строки предполагаемой связи.
export const ASSUMED_TEXT = 'предполагаемая связь: данных о коммутаторе нет';

// LegendItem — строка легенды: тип узла (значок и подпись).
export interface LegendItem {
  kind: string;
  label: string;
  icon: string;
}

// legendItems — типы, присутствующие на карте, в порядке KIND_ORDER;
// неизвестные типы добавляются в конец по алфавиту.
export function legendItems(g: Graph): LegendItem[] {
  const present = new Set<string>();
  for (const n of g.nodes) {
    present.add(n.kind);
  }
  const kinds = [...present].sort((a, b) => {
    const ia = KIND_ORDER.indexOf(a);
    const ib = KIND_ORDER.indexOf(b);
    if (ia !== -1 && ib !== -1) return ia - ib;
    if (ia !== -1) return -1;
    if (ib !== -1) return 1;
    return a.localeCompare(b);
  });
  return kinds.map((kind) => ({
    kind,
    label: KIND_LABELS[kind] ?? kind,
    icon: svgIcon(kind),
  }));
}

// hasAssumedLinks — есть ли на карте предполагаемые связи.
export function hasAssumedLinks(g: Graph): boolean {
  return g.links.some((l) => l.source === 'assumed');
}

// renderLegend — заливает контейнер легенды: строки типов, строки
// статусов (только присутствующие, NR-033 п.5) и пунктирные строки
// предполагаемых и ручных связей. Повторный вызов перезаливает
// содержимое.
export function renderLegend(container: HTMLElement, g: Graph, statuses?: GraphStatuses): void {
  container.textContent = '';
  const items = legendItems(g);
  const statusItems = presentStatuses(g, statuses);
  if (items.length === 0 && statusItems.length === 0 && !hasAssumedLinks(g) && !hasManualLinks(g)) {
    container.hidden = true;
    return;
  }
  container.hidden = false;
  for (const s of statusItems) {
    const chip = document.createElement('span');
    chip.className = `legend-item legend-status status-${s.status}`;
    chip.dataset.status = s.status;
    const mark = document.createElement('span');
    mark.className = 'legend-mark';
    mark.textContent = s.glyph;
    mark.setAttribute('aria-hidden', 'true');
    chip.append(mark, document.createTextNode(s.label));
    container.append(chip);
  }
  for (const item of items) {
    const chip = document.createElement('span');
    chip.className = 'legend-item';
    chip.dataset.kind = item.kind;
    const img = document.createElement('img');
    img.src = item.icon;
    img.alt = '';
    img.width = 16;
    img.height = 16;
    chip.append(img, document.createTextNode(item.label));
    container.append(chip);
  }
  if (hasAssumedLinks(g)) {
    const chip = document.createElement('span');
    chip.className = 'legend-item legend-assumed';
    chip.dataset.kind = 'assumed';
    const line = document.createElement('span');
    line.className = 'legend-dash';
    line.setAttribute('aria-hidden', 'true');
    chip.append(line, document.createTextNode(ASSUMED_TEXT));
    container.append(chip);
  }
  if (hasManualLinks(g)) {
    const chip = document.createElement('span');
    chip.className = 'legend-item legend-manual';
    chip.dataset.kind = 'manual';
    const line = document.createElement('span');
    line.className = 'legend-dash legend-dash-manual';
    line.setAttribute('aria-hidden', 'true');
    chip.append(line, document.createTextNode(MANUAL_TEXT));
    container.append(chip);
  }
}
