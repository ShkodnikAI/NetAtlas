// Граф карты сети на cytoscape: связи различаются стилем линии по
// источнику (lldp/fdb — сплошные, inferred — пунктир, manual —
// пунктир с подписью «вручную»); ручные и непроверенные элементы
// помечены.

import cytoscape from 'cytoscape';
import type { Core, ElementDefinition, EventObject, NodeSingular } from 'cytoscape';
import type { Graph, LinkInfo, NodeInfo } from './api';
import { badges, nodeStyle } from './nodes';

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
  manual: '#F5B83D',
};

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
        selector: 'node.unverified',
        style: { 'border-style': 'dashed' },
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
  return cy;
}

// nodeInfoOf — данные узла cytoscape в NodeInfo API.
function nodeInfoOf(n: NodeSingular): NodeInfo {
  return {
    id: String(n.data('id') ?? ''),
    kind: String(n.data('kind') ?? 'unknown'),
    label: String(n.data('label') ?? ''),
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

// setGraph перезаливает данные графа, сохраняя позиции узлов.
export function setGraph(cy: Core, g: Graph): void {
  const positions = new Map<string, { x: number; y: number }>();
  cy.nodes().forEach((n) => {
    positions.set(n.id(), n.position());
  });
  cy.elements().remove();

  const elements: ElementDefinition[] = [];
  for (const n of g.nodes) {
    const st = nodeStyle(n);
    elements.push({
      group: 'nodes',
      data: {
        id: n.id,
        kind: n.kind,
        label: nodeLabel(n),
        icon: st.icon,
        manual: n.manual,
        verified: n.verified,
        kindLabel: st.kindLabel,
        aria: `${st.kindLabel}: ${n.label}`,
      },
      position: positions.get(n.id) ?? { x: 0, y: 0 },
      style: { shape: st.shape, width: String(st.width), height: String(st.height) },
      classes: n.manual && !n.verified ? 'unverified' : '',
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
        dashed: l.source === 'inferred' || l.manual ? 'true' : 'false',
        // полные поля для панели и callbacks
        a: l.a, aPort: l.aPort, b: l.b, bPort: l.bPort,
        src: l.source, manual: l.manual, verified: l.verified,
      },
    });
  }
  cy.add(elements);
  void cy
    .layout({ name: 'cose', animate: false, randomize: positions.size === 0 })
    .run();
}

// nodeLabel — имя узла с метками «вручную» / «не проверен».
function nodeLabel(n: NodeInfo): string {
  let label = n.label || n.id;
  const marks = badges(n);
  if (marks.length > 0) label += `\n(${marks.join(', ')})`;
  return label;
}

function edgeLabel(l: LinkInfo): string {
  if (l.manual) return 'вручную';
  if (!l.verified) return 'не проверен';
  return '';
}

function edgeId(l: LinkInfo): string {
  return `${l.a}|${l.aPort}|${l.b}|${l.bPort}`;
}
