// Точки изгиба на линиях карты (NR-038 п.1): двойной клик по связи
// добавляет узловую точку, перетаскивание двигает её по мелкой сетке,
// двойной клик/Delete/контекстное меню удаляют. Линия проходит точки
// по порядку и всегда ортогонально (горизонтальные и вертикальные
// сегменты, как в NR-033): ломаная строится ногами «вниз-вбок» между
// соседними опорными точками. Математика чистая — тестируется без
// cytoscape; привязка к cy — в graph.ts.

import type { Core, EdgeSingular, NodeSingular } from 'cytoscape';
import { snapToGrid } from './layout';

// Point — модельные координаты карты.
export interface Point {
  x: number;
  y: number;
}

// orthogonalPolyline — вершины ломаной от src до dst через точки
// изгиба (по порядку): между соседними опорными точками — вертикаль,
// затем горизонталь. Совпадающие вершины схлопываются: нулевые
// сегменты не рисуются.
export function orthogonalPolyline(src: Point, dst: Point, waypoints: readonly Point[]): Point[] {
  const anchors = [src, ...waypoints, dst];
  const out: Point[] = [{ ...src }];
  for (let i = 0; i < anchors.length - 1; i++) {
    const a = anchors[i] as Point;
    const b = anchors[i + 1] as Point;
    if (a.x !== b.x && a.y !== b.y) {
      // Колено: вертикаль от a, горизонталь до b. У промежуточной
      // точки изгиба вход горизонтальный, выход вертикальный — точка
      // стоит на изломе линии.
      out.push({ x: a.x, y: b.y });
    }
    out.push({ ...b });
  }
  return dedupPoints(out);
}

// dedupPoints — соседние совпадающие вершины схлопываются.
export function dedupPoints(pts: readonly Point[]): Point[] {
  const out: Point[] = [];
  for (const p of pts) {
    const last = out[out.length - 1];
    if (last !== undefined && Math.abs(last.x - p.x) < 1e-9 && Math.abs(last.y - p.y) < 1e-9) {
      continue;
    }
    out.push({ x: p.x, y: p.y });
  }
  return out;
}

// WeightsDistances — точки ломаной в координатах cytoscape
// (curve-style: segments, edge-distances: node-position): каждая
// точка = src + w·(dst−src) + n·d, где n = (−uy, ux) — нормаль оси
// источник→цель. Точное представление любой точки плоскости, пока
// концы не совпадают.
export interface WeightsDistances {
  wts: number[];
  dss: number[];
}

// toWeightsDistances — перевод вершин ломаной (без концов) в wts/dss.
export function toWeightsDistances(src: Point, dst: Point, inner: readonly Point[]): WeightsDistances {
  const dx = dst.x - src.x;
  const dy = dst.y - src.y;
  const len2 = dx * dx + dy * dy;
  const wts: number[] = [];
  const dss: number[] = [];
  if (len2 < 1e-12) return { wts, dss };
  for (const p of inner) {
    const px = p.x - src.x;
    const py = p.y - src.y;
    // w — проекция на ось (доля пути от src к dst), d — смещение по
    // нормали (−uy, ux) — ровно так cytoscape считает segpts.
    wts.push((px * dx + py * dy) / len2);
    dss.push((py * dx - px * dy) / Math.sqrt(len2));
  }
  return { wts, dss };
}

// linkWaypointsOf — точки изгиба связи из wts/dss обратно в
// координаты (для проверок и отладки).
export function pointsFromWeights(src: Point, dst: Point, wts: readonly number[], dss: readonly number[]): Point[] {
  const dx = dst.x - src.x;
  const dy = dst.y - src.y;
  const len = Math.hypot(dx, dy);
  const nx = -dy / (len || 1);
  const ny = dx / (len || 1);
  const out: Point[] = [];
  for (let i = 0; i < Math.min(wts.length, dss.length); i++) {
    const w = wts[i] ?? 0;
    const d = dss[i] ?? 0;
    out.push({ x: src.x + w * dx + nx * d, y: src.y + w * dy + ny * d });
  }
  return out;
}

// --- состояние на cy -------------------------------------------------------

// WaypointState — точки изгиба карты: ключ связи → точки по порядку.
export type WaypointState = Map<string, Point[]>;

// cyState — состояние, привязанное к экземпляру карты.
interface CyWaypoints {
  // points — ключ связи → текущие точки (источник истины после
  // applyWaypoints; во время перетаскивания подтягиваются из узлов).
  points: Map<string, Point[]>;
  // onChange — вызывается после изменения точек (не при загрузке).
  onChange: ((dirty: string[]) => void) | null;
}

const CY_STATE = new WeakMap<Core, CyWaypoints>();

function stateOf(cy: Core): CyWaypoints {
  let st = CY_STATE.get(cy);
  if (st === undefined) {
    st = { points: new Map(), onChange: null };
    CY_STATE.set(cy, st);
  }
  return st;
}

// onWaypointsChanged — подписка на изменения точек (сохранение на
// сервере в main.ts).
export function onWaypointsChanged(cy: Core, cb: (dirty: string[]) => void): void {
  stateOf(cy).onChange = cb;
}

// waypointsOf — текущие точки всех связей (снимок для сохранения).
export function waypointsOf(cy: Core): WaypointState {
  const out: WaypointState = new Map();
  for (const [key, pts] of stateOf(cy).points) {
    out.set(key, pts.map((p) => ({ ...p })));
  }
  return out;
}

// waypointPrefix — префикс id узлов-точек изгиба.
export const waypointPrefix = 'wp:';

// waypointId — id узла-точки: префикс, ключ связи, индекс.
export function waypointId(linkKey: string, idx: number): string {
  return `${waypointPrefix}${linkKey}:${idx}`;
}

// applyWaypoints — залить точки изгиба (с сервера) на карту: узлы-
// точки и ломаные связей. Не вызывает onChange: это загрузка, а не
// правка владельца. Ключи без связей на карте пропускаются.
export function applyWaypoints(cy: Core, wps: WaypointState): void {
  const st = stateOf(cy);
  st.points = new Map();
  cy.nodes(`.${WAYPOINT_CLASS}`).remove();
  // Индекс: ключ связи → id ребра (ключ приходит с сервера, ребро
  // ищется по data(wpKey)).
  const edgeByKey = new Map<string, EdgeSingular>();
  cy.edges().forEach((e) => {
    const key = String(e.data('wpKey') ?? '');
    if (key !== '') edgeByKey.set(key, e);
  });
  for (const [key, pts] of wps) {
    const e = edgeByKey.get(key);
    if (e === undefined || e.removed()) continue;
    st.points.set(key, pts.map((p) => ({ ...p })));
    rebuildWaypointNodes(cy, e, key, st.points.get(key) as Point[]);
  }
  recomputeWaypointEdges(cy);
}

// clearAllWaypoints — убрать все точки изгиба с карты (после очистки
// на сервере).
export function clearAllWaypoints(cy: Core): void {
  const st = stateOf(cy);
  st.points = new Map();
  cy.nodes(`.${WAYPOINT_CLASS}`).remove();
  cy.edges().forEach((e) => {
    if (e.data('haswp') !== undefined) {
      e.removeData('haswp');
      e.removeData('wts');
      e.removeData('dss');
    }
  });
}

// clearLinkWaypoints — убрать точки одной связи (кнопка «Сбросить
// изгибы связи»). Аргумент — id связи cytoscape (выбранная линия);
// ключ точек берётся из данных связи. onChange вызывается, если
// что-то снято.
export function clearLinkWaypoints(cy: Core, edgeId: string): void {
  const st = stateOf(cy);
  const e = cy.getElementById(edgeId).first();
  const key = e.nonempty() ? String(e.data('wpKey') ?? '') : edgeId;
  if (key === '' || !st.points.has(key)) return;
  st.points.delete(key);
  cy.nodes(`.${WAYPOINT_CLASS}`).forEach((n) => {
    if (String(n.data('wpLink')) === key) n.remove();
  });
  if (e.nonempty()) {
    e.removeData('haswp');
    e.removeData('wts');
    e.removeData('dss');
  }
  st.onChange?.([key]);
}

// addWaypoint — двойной клик по связи: точка в месте клика,
// привязанная к мелкой сетке 20×20 (NR-038 п.1).
export function addWaypoint(cy: Core, e: EdgeSingular, pos: Point): void {
  const key = String(e.data('wpKey') ?? '');
  if (key === '') return;
  const st = stateOf(cy);
  const pts = st.points.get(key) ?? [];
  const snapped = snapPoint(pos);
  if (pts.length >= MAX_WAYPOINTS_PER_LINK) return;
  pts.push(snapped);
  st.points.set(key, pts);
  rebuildWaypointNodes(cy, e, key, pts);
  recomputeWaypointEdges(cy);
  st.onChange?.([key]);
}

// removeWaypoint — удалить точку (двойной клик по ней, Delete,
// контекстное меню).
export function removeWaypoint(cy: Core, n: NodeSingular): void {
  const key = String(n.data('wpLink') ?? '');
  if (key === '') return;
  const st = stateOf(cy);
  const pts = st.points.get(key);
  if (pts === undefined) return;
  const idx = Number(n.data('wpIdx'));
  if (!Number.isInteger(idx) || idx < 0 || idx >= pts.length) return;
  pts.splice(idx, 1);
  if (pts.length === 0) st.points.delete(key);
  const e = edgeByKeyOf(cy, key);
  if (e !== undefined && e.inside()) {
    rebuildWaypointNodes(cy, e, key, pts);
  } else {
    cy.nodes(`.${WAYPOINT_CLASS}`).forEach((w) => {
      if (String(w.data('wpLink')) === key) w.remove();
    });
  }
  recomputeWaypointEdges(cy);
  st.onChange?.([key]);
}

// moveWaypoint — перетаскивание закончено: привязка к мелкой сетке
// при включённой «Привязке к сетке», пересчёт линии, сохранение.
export function moveWaypoint(cy: Core, n: NodeSingular, snapOn: boolean): void {
  if (snapOn) {
    const p = n.position();
    n.position(snapPoint(p));
  }
  syncWaypointNodes(cy);
  recomputeWaypointEdges(cy);
  const key = String(n.data('wpLink') ?? '');
  if (key !== '') stateOf(cy).onChange?.([key]);
}

// MAX_WAYPOINTS_PER_LINK — верхняя граница на клиенте (серверная —
// store.MaxWaypointsPerLink): точки сверх лимита не добавляются.
export const MAX_WAYPOINTS_PER_LINK = 64;

// WAYPOINT_CLASS — класс узлов-точек изгиба (стиль в graph.ts).
export const WAYPOINT_CLASS = 'waypoint';

// snapPoint — привязка к узлу мелкой сетки 20×20 (GRID_STEP,
// константа в layout.ts).
export function snapPoint(p: Point): Point {
  return snapToGrid(p.x, p.y);
}

// rebuildWaypointNodes — пересобрать узлы-точки одной связи: id
// привязаны к индексу, после удаления индексы сдвигаются.
function rebuildWaypointNodes(cy: Core, e: EdgeSingular, key: string, pts: Point[]): void {
  cy.nodes(`.${WAYPOINT_CLASS}`).forEach((n) => {
    if (String(n.data('wpLink')) === key) n.remove();
  });
  const color = String(e.data('color') ?? '#7C8798');
  pts.forEach((p, i) => {
    cy.add({
      group: 'nodes',
      data: {
        id: waypointId(key, i),
        wpLink: key,
        wpIdx: i,
        color,
      },
      position: { x: p.x, y: p.y },
      classes: WAYPOINT_CLASS,
    });
  });
}

// edgeByKeyOf — ребро по ключу связи.
function edgeByKeyOf(cy: Core, key: string): EdgeSingular | undefined {
  let found: EdgeSingular | undefined;
  cy.edges().forEach((e) => {
    if (String(e.data('wpKey') ?? '') === key) found = e;
  });
  return found;
}

// syncWaypointNodes — подтянуть точки состояния из позиций узлов:
// во время перетаскивания линия следует за курсором.
export function syncWaypointNodes(cy: Core): void {
  const st = stateOf(cy);
  cy.nodes(`.${WAYPOINT_CLASS}`).forEach((n) => {
    const key = String(n.data('wpLink') ?? '');
    const idx = Number(n.data('wpIdx'));
    const pts = st.points.get(key);
    if (pts === undefined || !Number.isInteger(idx) || idx < 0 || idx >= pts.length) return;
    pts[idx] = { x: n.position('x'), y: n.position('y') };
  });
}

// recomputeWaypointEdges — пересчитать ломаные всех связей с точками
// изгиба: сегменты от текущих позиций концов через точки по порядку.
// Концы совпали (узлы наложены) — ребро оставляется в прежнем виде.
export function recomputeWaypointEdges(cy: Core): void {
  const st = stateOf(cy);
  if (st.points.size === 0) return;
  cy.edges().forEach((e) => {
    const key = String(e.data('wpKey') ?? '');
    const pts = key === '' ? undefined : st.points.get(key);
    if (pts === undefined || pts.length === 0) {
      if (e.data('haswp') !== undefined) {
        e.removeData('haswp');
        e.removeData('wts');
        e.removeData('dss');
      }
      return;
    }
    const src = e.source().position();
    const dst = e.target().position();
    const line = orthogonalPolyline(src, dst, pts);
    const inner = line.slice(1, -1);
    if (inner.length === 0) return; // точки совпали с концами
    const { wts, dss } = toWeightsDistances(src, dst, inner);
    if (wts.length === 0) return;
    e.data('haswp', 'true');
    e.data('wts', wts);
    e.data('dss', dss);
  });
}
