// Граф карты сети на cytoscape: связи различаются стилем линии по
// источнику (lldp/fdb — сплошные, inferred — пунктир, assumed —
// пунктир другого цвета (NR-032 п.3), manual — пунктир с подписью
// «вручную»); ручные и непроверенные элементы помечены. NR-031:
// «не проверен» — маркер на узле, а не строка в подписи; длинные
// подписи обрезаются с подсказкой; подписи не пересекаются.
// NR-032: детерминированная раскладка сеткой (п.4), скрытый a11y-слой
// с data-kind для скринридеров и сквозных тестов (п.6).

import cytoscape from 'cytoscape';
import type { Core, ElementDefinition, EventObject, NodeSingular } from 'cytoscape';
import type { Graph, LinkInfo, NodeInfo } from './api';
import { nodeStyle } from './nodes';
import { arrangeGrid, deoverlap, measureLabel, type Positioned } from './layout';

export interface GraphCallbacks {
  // Клик по узлу (или выбор с клавиатуры).
  onNodeSelect: (node: NodeInfo | null) => void;
  // Клик по связи (для разрыва ручной связи): вторым — id связи cytoscape.
  onLinkSelect: (link: LinkInfo | null, edgeId: string | null) => void;
}

const STROKE: Record<string, string> = {
  lldp: '#7C8798',
  fdb: '#5F6B7B',
  inferred: '#8FB8E8',
  assumed: '#B48FE8',
  manual: '#F5B83D',
};

// Подпись узла длиннее этого числа знаков обрезается многоточием;
// полная подпись остаётся в data(fullLabel) для подсказки.
const LABEL_MAX_CHARS = 28;

export function truncateLabel(text: string, max = LABEL_MAX_CHARS): string {
  if (text.length <= max) return text;
  return text.slice(0, Math.max(1, max - 1)) + '…';
}

export function createGraph(
  container: HTMLElement,
  cb: GraphCallbacks,
): Core {
  const cy = cytoscape({
    container,
    elements: [],
    style: [
      {
        selector: 'node',
        style: {
          'background-color': '#1B2430',
          'background-image': 'data(icon)',
          'background-fit': 'contain',
          'background-opacity': 1,
          'border-width': 2,
          'border-color': '#2E3A4C',
          color: '#E6EAF0',
          'font-size': 11,
          'font-family': 'system-ui, sans-serif',
          'text-valign': 'bottom',
          'text-margin-y': 6,
          'text-wrap': 'wrap',
          'text-max-width': '140',
          width: '40',
          height: '32',
          label: 'data(label)',
        },
      },
      {
        selector: 'node[manual]',
        style: { 'border-color': '#F5B83D' },
      },
      {
        // NR-031 п.4: «не проверен» — жёлтый ореол вокруг узла, а не
        // строка в подписи.
        selector: 'node.unverified',
        style: {
          'border-style': 'dashed',
          'overlay-color': '#F5B83D',
          'overlay-opacity': 0.55,
          'overlay-padding': 3,
        },
      },
      {
        selector: 'edge',
        style: {
          width: 1.6,
          'line-color': 'data(color)',
          'target-arrow-color': 'data(color)',
          'curve-style': 'straight',
          color: '#9AA6B5',
          'font-size': 10,
          label: 'data(label)',
          'text-background-color': '#0E1116',
          'text-background-opacity': 1,
          'text-background-padding': '2',
        },
      },
      {
        selector: 'edge[dashed]',
        style: { 'line-style': 'dashed' },
      },
      {
        selector: ':selected',
        style: { 'border-color': '#5AA9FF', 'line-color': '#5AA9FF' },
      },
    ],
    layout: { name: 'cose', animate: false, randomize: false },
    wheelSensitivity: 0.2,
  });

  cy.on('tap', 'node', (ev: EventObject) => {
    const n = ev.target as NodeSingular;
    cb.onNodeSelect(nodeInfoOf(n));
    cb.onLinkSelect(null, null);
  });
  cy.on('tap', 'edge', (ev: EventObject) => {
    const e = ev.target;
    cb.onLinkSelect(linkInfoOf(e), e.id());
  });
  cy.on('tap', (ev: EventObject) => {
    if (ev.target === cy) {
      cb.onNodeSelect(null);
      cb.onLinkSelect(null, null);
    }
  });

  setupTooltip(cy, container);
  return cy;
}

// setupTooltip — всплывающая подсказка с полной подписью узла
// (NR-031 п.4): обрезанная подпись на карте, полный текст в подсказке.
function setupTooltip(cy: Core, container: HTMLElement): void {
  const tip = document.getElementById('graph-tooltip');
  if (tip === null) return;
  const show = (n: NodeSingular | null): void => {
    if (n === null) {
      tip.hidden = true;
      tip.textContent = '';
      return;
    }
    const full = String(n.data('fullLabel') ?? n.data('label') ?? '');
    const kind = String(n.data('kindLabel') ?? '');
    const marks = String(n.data('marks') ?? '');
    tip.textContent = marks === '' ? `${full}\n${kind}` : `${full}\n${kind}\n${marks}`;
    tip.hidden = false;
    const rect = container.getBoundingClientRect();
    const pos = n.renderedPosition();
    const x = pos.x + 14;
    const y = pos.y + 14;
    tip.style.left = `${Math.min(x, Math.max(0, rect.width - 330))}px`;
    tip.style.top = `${Math.min(y, Math.max(0, rect.height - 80))}px`;
  };
  cy.on('mouseover', 'node', (ev: EventObject) => show(ev.target as NodeSingular));
  cy.on('mouseout', 'node', () => show(null));
  cy.on('drag', 'node', () => show(null));
}

// nodeInfoOf — данные узла cytoscape в NodeInfo API.
function nodeInfoOf(n: NodeSingular): NodeInfo {
  return {
    id: String(n.data('id') ?? ''),
    kind: String(n.data('kind') ?? 'unknown'),
    label: String(n.data('fullLabel') ?? n.data('label') ?? ''),
    manual: Boolean(n.data('manual')),
    verified: Boolean(n.data('verified')),
  };
}

// linkInfoOf — данные связи cytoscape в LinkInfo API.
function linkInfoOf(e: cytoscape.EdgeSingular): LinkInfo {
  return {
    a: String(e.data('a') ?? ''),
    aPort: String(e.data('aPort') ?? ''),
    b: String(e.data('b') ?? ''),
    bPort: String(e.data('bPort') ?? ''),
    source: String(e.data('src') ?? ''),
    manual: Boolean(e.data('manual')),
    verified: Boolean(e.data('verified')),
  };
}

// setGraph перезаливает данные графа, сохраняя позиции узлов;
// раскладка детерминированная (NR-032 п.4): узлы без сохранённой
// позиции выстраиваются сеткой (шлюз сверху, ряды по типам), узлы,
// сдвинутые владельцем (saved), не трогаются.
export function setGraph(cy: Core, g: Graph, saved?: ReadonlySet<string>): void {
  const positions = new Map<string, { x: number; y: number }>();
  cy.nodes().forEach((n) => {
    positions.set(n.id(), n.position());
  });
  cy.elements().remove();

  const elements: ElementDefinition[] = [];
  let hasGuests = false;
  for (const n of g.nodes) {
    const st = nodeStyle(n);
    hasGuests = hasGuests || n.class === 'guest';
    elements.push({
      group: 'nodes',
      data: {
        id: n.id,
        kind: n.kind,
        label: nodeLabel(n),
        fullLabel: n.label || n.id,
        marks: nodeMarks(n).join(', '),
        icon: st.icon,
        manual: n.manual,
        verified: n.verified,
        kindLabel: st.kindLabel,
        aria: `${st.kindLabel}: ${n.label}`,
        // Гости объединяются группой «Гостевая сеть» (compound).
        parent: n.class === 'guest' ? 'grp-guest' : undefined,
      },
      position: positions.get(n.id) ?? { x: 0, y: 0 },
      style: { shape: st.shape, width: String(st.width), height: String(st.height) },
      classes: [n.manual ? 'manual' : '', n.verified ? '' : 'unverified']
        .filter(Boolean)
        .join(' '),
    });
  }
  if (hasGuests) {
    elements.push({
      group: 'nodes',
      data: { id: 'grp-guest', label: 'Гостевая сеть' },
      style: {
        shape: 'round-rectangle',
        'background-opacity': '0.06',
        'border-style': 'dashed',
        'border-color': '#8FB8E8',
        'font-size': '12',
        color: '#9AA6B5',
        'text-valign': 'top',
      },
    });
  }
  for (const l of g.links) {
    const color = STROKE[l.source] ?? STROKE['fdb'] ?? '#7C8798';
    elements.push({
      group: 'edges',
      data: {
        id: edgeId(l),
        source: l.a,
        target: l.b,
        color,
        label: edgeLabel(l),
        dashed: l.source === 'inferred' || l.source === 'assumed' || l.manual ? 'true' : 'false',
        // полные поля для панели и callbacks
        a: l.a, aPort: l.aPort, b: l.b, bPort: l.bPort,
        src: l.source, manual: l.manual, verified: l.verified,
      },
    });
  }
  cy.add(elements);
  arrangeMap(cy, g, saved ?? new Set());
  renderA11y(g);
}

// arrangeMap — детерминированная раскладка (NR-032 п.4): позиции
// узлов без сохранённого смещения — из arrangeGrid (шлюз сверху,
// ряды по типам); затем deoverlap для защиты от пересечений, если
// сохранённые позиции влезли в сетку.
function arrangeMap(cy: Core, g: Graph, saved: ReadonlySet<string>): void {
  const nodeEls: NodeSingular[] = [];
  cy.nodes().forEach((n) => {
    if (!n.isParent()) nodeEls.push(n);
  });
  const kinds = new Map(g.nodes.map((n) => [n.id, n.kind]));
  const grid = arrangeGrid(
    nodeEls.map((n) => ({
      id: n.id(),
      kind: kinds.get(n.id()) ?? 'unknown',
      label: String(n.data('label') ?? ''),
    })),
    saved,
  );
  for (const n of nodeEls) {
    const p = grid.get(n.id());
    if (p !== undefined) n.position({ x: p.x, y: p.y });
  }
  // Пересечения разводятся только среди автоматически расставленных:
  // узлы владельца не сдвигаются.
  const auto: Positioned[] = nodeEls
    .filter((n) => grid.has(n.id()))
    .map((n) => ({
      id: n.id(),
      x: n.position('x'),
      y: n.position('y'),
      label: measureLabel(String(n.data('label') ?? '')),
    }));
  deoverlap(auto);
  for (const p of auto) {
    const n = cy.$id(p.id).first() as NodeSingular | undefined;
    if (n !== undefined) n.position({ x: p.x, y: p.y });
  }
  // Прочие (сохранённые) участвуют в деоверкапе, только если сетка
  // наехала на них — они сдвигаются минимально.
  const others: Positioned[] = nodeEls
    .filter((n) => !grid.has(n.id()) && saved.has(n.id()))
    .map((n) => ({
      id: n.id(),
      x: n.position('x'),
      y: n.position('y'),
      label: measureLabel(String(n.data('label') ?? '')),
    }));
  if (others.length > 0) {
    const combined: Positioned[] = [...auto, ...others];
    deoverlap(combined);
    for (const p of combined) {
      const n = cy.$id(p.id).first() as NodeSingular | undefined;
      if (n !== undefined) n.position({ x: p.x, y: p.y });
    }
  }
}

// renderA11y — скрытый список узлов для скринридеров и сквозных
// тестов (NR-032 п.6): каждый узел — строка с data-kind и типом.
export function renderA11y(g: Graph): void {
  const box = document.getElementById('map-a11y');
  if (box === null) return;
  box.textContent = '';
  for (const n of g.nodes) {
    const li = document.createElement('li');
    li.dataset.kind = n.kind;
    li.dataset.id = n.id;
    const st = nodeStyle(n);
    li.textContent = `${n.label} — ${st.kindLabel}`;
    box.append(li);
  }
}

// nodeLabel — короткая подпись узла: длинный текст обрезается
// многоточием (полный — в data(fullLabel)); «не проверен» в подпись
// не попадает (маркер на узле).
function nodeLabel(n: NodeInfo): string {
  const base = truncateLabel(n.label || n.id);
  const marks = nodeMarks(n).filter((m) => m !== 'не проверен');
  if (marks.length > 0) return `${base}\n(${marks.join(', ')})`;
  return base;
}

// nodeMarks — метки для подсказки и панели: «вручную», «не проверен»,
// «без агента».
function nodeMarks(n: NodeInfo): string[] {
  const out: string[] = [];
  if (n.manual) out.push('вручную');
  if (!n.verified) out.push('не проверен');
  if (n.class === 'known_no_agent') out.push('без агента');
  return out;
}

// edgeLabel — подпись связи: ручная помечается, предполагаемая
// объясняется легендой (NR-032 п.3), непроверенная — маркером.
function edgeLabel(l: LinkInfo): string {
  if (l.manual) return 'вручную';
  if (l.source === 'assumed') return '';
  if (!l.verified) return 'не проверен';
  return '';
}

function edgeId(l: LinkInfo): string {
  return `${l.a}|${l.aPort}|${l.b}|${l.bPort}`;
}
