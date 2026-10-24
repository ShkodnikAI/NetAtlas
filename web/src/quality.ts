// Экран «Качество сети» (NR-008): матрица «агент × цель», график
// скорости за сутки, список узких мест. Значения сервера — текстом.

import type { Finding } from './api';

export interface QualityCell {
  agent_id: string;
  target: string;
  latest: Record<string, number>;
  worst: string;
}

export interface Bottleneck {
  agent_id: string;
  hostname: string;
  finding: Finding;
}

export interface SeriesPoint {
  window: string;
  avg: number;
  p95: number;
  max: number;
}

function el(tag: string, cls: string, text?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls !== '') e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

const worstNames: Record<string, string> = {
  ok: 'норма',
  info: 'информация',
  warning: 'предупреждение',
  critical: 'критично',
};

// cellWorst — худшее состояние по видам метрик ячейки (пороги
// применены на сервере; здесь — подпись).
export function cellWorst(latest: Record<string, number>): string {
  const loss = latest['loss'];
  if (loss !== undefined && loss > 0.05) return 'critical';
  if (loss !== undefined && loss > 0.02) return 'warning';
  const lat = latest['latency'];
  if (lat !== undefined && lat > 50) return 'warning';
  return 'ok';
}

// renderQualityMatrix — таблица матрицы.
export function renderQualityMatrix(root: HTMLElement, cells: QualityCell[]): void {
  root.textContent = '';
  if (cells.length === 0) {
    root.append(el('p', 'muted', 'нет данных: замеров нет'));
    return;
  }
  const table = el('table', 'data-table');
  const thead = el('thead', '');
  const hr = el('tr', '');
  for (const h of ['Агент', 'Цель', 'Задержка, мс', 'Потери', 'Состояние']) {
    hr.append(el('th', '', h));
  }
  thead.append(hr);
  table.append(thead);
  const tbody = el('tbody', '');
  for (const c of cells) {
    const tr = el('tr', '');
    tr.append(el('td', '', c.agent_id));
    tr.append(el('td', '', c.target));
    tr.append(el('td', '', c.latest['latency'] !== undefined ? c.latest['latency'].toFixed(1) : '—'));
    tr.append(el('td', '', c.latest['loss'] !== undefined ? `${(c.latest['loss'] * 100).toFixed(1)}%` : '—'));
    const worst = c.worst !== 'ok' ? c.worst : cellWorst(c.latest);
    tr.append(el('td', `severity-${worst}`, worstNames[worst] ?? worst));
    tbody.append(tr);
  }
  table.append(tbody);
  root.append(table);
}

// svgPolyline — простой график ряда (SVG, без зависимостей).
export function svgPolyline(points: SeriesPoint[], width: number, height: number): SVGSVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('width', '100%');
  svg.setAttribute('height', String(height));
  svg.classList.add('quality-graph');
  if (points.length < 2) {
    return svg;
  }
  const maxV = Math.max(...points.map((p) => p.max), 1);
  const stepX = width / (points.length - 1);
  const line = (pick: (p: SeriesPoint) => number): string =>
    points.map((p, i) => `${(i * stepX).toFixed(1)},${(height - (pick(p) / maxV) * (height - 4) - 2).toFixed(1)}`).join(' ');
  const mk = (pts: string, cls: string): SVGPolylineElement => {
    const pl = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
    pl.setAttribute('points', pts);
    pl.setAttribute('fill', 'none');
    pl.setAttribute('class', cls);
    return pl;
  };
  svg.append(mk(line((p) => p.max), 'g-max'));
  svg.append(mk(line((p) => p.p95), 'g-p95'));
  svg.append(mk(line((p) => p.avg), 'g-avg'));
  return svg;
}

// renderBottlenecks — список узких мест.
export function renderBottlenecks(root: HTMLElement, list: Bottleneck[]): void {
  root.textContent = '';
  if (list.length === 0) {
    root.append(el('p', 'muted', 'узких мест не найдено'));
    return;
  }
  for (const b of list) {
    const div = el('div', `finding severity-${b.finding.severity}`);
    div.append(el('span', 'finding-fact', `${b.hostname}: ${b.finding.fact}`));
    div.append(el('div', 'muted', `рекомендация: ${b.finding.advice}`));
    root.append(div);
  }
}

// renderQuality — весь экран.
export function renderQuality(
  root: HTMLElement,
  cells: QualityCell[],
  bottlenecks: Bottleneck[],
  series: SeriesPoint[],
): void {
  const matrix = root.querySelector('#quality-matrix') as HTMLElement;
  const broot = root.querySelector('#quality-bottlenecks') as HTMLElement;
  const graph = root.querySelector('#quality-graph') as HTMLElement;
  renderQualityMatrix(matrix, cells);
  renderBottlenecks(broot, bottlenecks);
  graph.textContent = '';
  graph.append(svgPolyline(series, 600, 120));
}
