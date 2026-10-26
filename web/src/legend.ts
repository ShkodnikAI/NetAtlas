// Легенда карты (NR-032 п.3, п.5): внизу показываются типы узлов,
// которые есть на карте (значок + подпись), и — если на карте есть
// предполагаемые связи — пунктирная строка «предполагаемая связь:
// данных о коммутаторе нет». Функции чистые: legendItems вычисляет
// состав легенды, renderLegend рисует её в DOM (только textContent,
// данные API недоверенные).

import type { Graph } from './api';
import { KIND_LABELS, svgIcon } from './nodes';

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

// renderLegend — заливает контейнер легенды: строки типов и, при
// предполагаемых связях, пунктирная строка. Повторный вызов
// перезаливает содержимое.
export function renderLegend(container: HTMLElement, g: Graph): void {
  container.textContent = '';
  const items = legendItems(g);
  if (items.length === 0 && !hasAssumedLinks(g)) {
    container.hidden = true;
    return;
  }
  container.hidden = false;
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
}
