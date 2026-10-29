// Граф карты сети на cytoscape: связи различаются стилем линии по
// источнику (lldp/fdb — сплошные, inferred — пунктир, assumed —
// пунктир другого цвета (NR-032 п.3), manual — пунктир с подписью
// «вручную»); ручные и непроверенные элементы помечены. NR-031:
// «не проверен» — маркер на узле, а не строка в подписи; длинные
// подписи обрезаются с подсказкой; подписи не пересекаются.
// NR-032: детерминированная раскладка сеткой (п.4), скрытый a11y-слой
// с data-kind для скринридеров и сквозных тестов (п.6).
// NR-033: связи ортогональные (curve-style taxi, излом под прямым
// углом в зазоре между рядами), двойной клик открывает полную
// карточку, значки несут маркер статуса и счётчик решений.
// NR-037: точки соединений — порт-узлы 6 px на стыке линии с диском
// (syncBendDots), а не стрелки cytoscape: размер «кружка» считается
// как max(pow(w×13.37, 0.9), 29) × arrow-scale — при линии 1.6 и
// scale 4 это диск ~35 px, закрывавший подписи («фиолетовые круги»
// со скриншота владельца). Подписи читаются поверх линий: фон под
// цвет поля; магистраль — в нижней половине зазора между рядами,
// под подписями верхнего ряда; подпись шлюза — над диском.
// NR-036: значки — вариант В «Цвет по роли»: круглый диск 74 px с
// цветом по роли и белым глифом, кольцо статуса внутри SVG; рамка
// узла cytoscape не рисуется, выделение — яркая внешняя обводка
// #E6EAF0 (подложка под узлом), не меняющая цвет статуса.
// NR-038: точки изгиба на линиях — двойной клик по связи ставит
// узловую точку на мелкой сетке 20×20, перетаскивание двигает её,
// двойной клик/Delete/контекстное меню удаляют; линия всегда
// ортогональна (ломаная сегментами через точки, NR-033); точки
// хранятся на сервере (wpKey связи — из данных графа). Подписи:
// шрифт 13 px при масштабе 100% и не мельче 11 px экранных,
// перенос по словам без «…» посередине (syncLabelZoom, wrapLabel).

import cytoscape from 'cytoscape';
import type { Core, ElementDefinition, EventObject, NodeSingular } from 'cytoscape';
import type { Graph, LinkInfo, NodeInfo } from './api';
import { BADGE_NODE, nodeStyle, STATUS_STYLES, type NodeStatusKind } from './nodes';
import { arrangeGrid, deoverlap, measureLabel, wrapLabel, type Positioned } from './layout';
import {
  addWaypoint,
  moveWaypoint,
  recomputeWaypointEdges,
  removeWaypoint,
  syncWaypointNodes,
  WAYPOINT_CLASS,
  type Point,
} from './waypoints';

export interface GraphCallbacks {
  // Клик по узлу (или выбор с клавиатуры).
  onNodeSelect: (node: NodeInfo | null) => void;
  // Двойной клик по узлу: открыть полную карточку (NR-033 п.3).
  onNodeOpen: (node: NodeInfo) => void;
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

// Шрифт подписи узла (NR-038 п.3): 13 px при масштабе 100% —
// минимум; насыщенность 500.
export const LABEL_FONT_SIZE = 13;
// Экранный минимум подписи при малом масштабе: ниже 0.7 подписи не
// мельче 11 px экранных (шрифт в модельных единицах растёт).
export const LABEL_MIN_SCREEN_ZOOM = 0.7;
export const LABEL_MIN_SCREEN_SIZE = 11;

// Минимальный масштаб по умолчанию (NR-034 п.2, пересчёт NR-036):
// значок-диск 74 px модели при зуме 0.8 отрисовывается не мельче
// 59 px — мельче значки не сжимаются, карта прокручивается.
export const MIN_ICON_ZOOM = 0.8;
// Поля вокруг карты при подгонке и расчёте переноса ряда (px).
const FIT_PADDING = 90;

export function truncateLabel(text: string, max = 28): string {
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
          'background-color': 'rgba(0,0,0,0)',
          'background-image': 'data(icon)',
          'background-fit': 'contain',
          // NR-035 п.4: значок заполняет узел целиком — явный размер
          // фона снимает зависимость от intrinsic-размера SVG (без
          // него глиф рисовался крошечным в углу плашки).
          'background-width': '100%',
          'background-height': '100%',
          'background-position-x': '50%',
          'background-position-y': '50%',
          'background-opacity': 1,
          // NR-036: кольцо статуса рисуется внутри SVG-значка, рамка
          // узла не нужна — выделение не перекрашивает статус.
          'border-width': 0,
          color: '#E6EAF0',
          // NR-038 п.3: подпись читается — 13 px при масштабе 100%,
          // насыщенность 500, фон цвета поля с отступом 3 px;
          // при малом масштабе шрифт догоняется до 11 px экранных
          // (syncLabelZoom).
          'font-size': LABEL_FONT_SIZE,
          'font-weight': 500,
          'font-family': 'system-ui, sans-serif',
          'text-valign': 'bottom',
          'text-margin-y': 6,
          'text-wrap': 'wrap',
          'text-max-width': '140',
          // NR-037 п.2: подпись читается поверх линий — фон под цвет
          // поля с отступом 3 px (NR-038 п.3); узлы с подписями
          // рисуются выше рёбер сами (z-index-compare в cytoscape).
          'text-background-color': '#0E1116',
          'text-background-opacity': 1,
          'text-background-padding': '3',
          'text-background-shape': 'roundrectangle',
          width: String(BADGE_NODE),
          height: String(BADGE_NODE),
          label: 'data(label)',
        },
      },
      {
        // NR-036 п.3: выделение узла и режим «соединить» — яркая
        // внешняя обводка #E6EAF0 2 px. Рамка рисуется по границе
        // узла (38–40 px при значке 74) — вне кольца статуса, его
        // цвет не меняется.
        selector: 'node:selected, node.selected',
        style: {
          'border-width': 2,
          'border-color': '#E6EAF0',
        },
      },
      {
        selector: 'edge',
        style: {
          width: 1.6,
          'line-color': 'data(color)',
          // NR-037 п.1: стрелок нет — точки соединений рисуют
          // порт-узлы 6 px на стыке линии с диском (syncBendDots).
          // Стрелка-«кружок» cytoscape при линии 1.6 и arrow-scale 4
          // имеет диаметр ~35 px (min база 29 в формуле размера) и
          // ложилась ровно на подписи узлов и шлюза.
          'source-arrow-shape': 'none',
          'target-arrow-shape': 'none',
          // scale 1 держит отступ линии от диска (gap) 3.2 px — его
          // закрывает точка на границе; при scale 4 отступ 12.8 px
          // оставлял бы видимую щель.
          'arrow-scale': 1,
          // Ортогональные связи (NR-033 п.1): ломаная под прямыми
          // углами. taxi-direction vertical: вертикальный участок у
          // источника, горизонталь в зазоре между рядами. NR-037 п.2:
          // cytoscape считает taxi-turn от границы узла: 10 px от
          // границы = 50 px от центра — нижняя половина зазора между
          // рядами (шаг ряда 120, диск 80). Раньше 20 px = 60 px от
          // центра — ровно по нижнему краю подписей верхнего ряда
          // (подпись висит на 6..20 px ниже диска, до y−60), и
          // магистраль перечёркивала подписи. Теперь между подписью
          // (до y−60) и диском (от y−40) свободная полоса y−60..y−40,
          // магистраль — на y−50, посередине.
          'curve-style': 'taxi',
          'taxi-direction': 'vertical',
          'taxi-turn': '10px',
          'taxi-turn-min-distance': 8,
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
        // NR-036: цвет выделенных связей; рамка узлов при выделении
        // не перекрашивается (кольцо статуса остаётся цветом статуса).
        selector: ':selected',
        style: {
          'line-color': '#5AA9FF',
          'source-arrow-color': '#5AA9FF',
          'target-arrow-color': '#5AA9FF',
        },
      },
      {
        // Точки на изломах ортогональных линий (NR-035 п.2):
        // порт-узлы без событий и перетаскивания.
        selector: 'node.bend',
        style: {
          width: 6,
          height: 6,
          shape: 'ellipse',
          'background-color': 'data(color)',
          'background-opacity': 1,
          'border-width': 0,
          label: '',
          events: 'no',
          // NR-037 п.1: точки ниже узлов и их подписей (среди узлов
          // порядок по z-index, затем по добавлению), но выше линий —
          // z-index-compare всегда рисует узлы над рёбрами.
          'z-index': -1,
        },
      },
      {
        // Связь с пользовательскими точками изгиба (NR-038 п.1):
        // ломаная из сегментов через точки по порядку, всегда
        // ортогонально. Точки пересчитываются в wts/dss относительно
        // оси источник→цель (edge-distances: node-position — от
        // центров узлов) при каждом изменении позиций.
        selector: 'edge[haswp]',
        style: {
          'curve-style': 'segments',
          'edge-distances': 'node-position',
          'segment-weights': 'data(wts)',
          'segment-distances': 'data(dss)',
        },
      },
      {
        // Пользовательская точка изгиба (NR-038 п.1): 10 px, обводка
        // цветом фона 2 px, события и перетаскивание включены —
        // отличается от автоматических точек излома 6 px; при
        // выделении обводка подсвечивается.
        selector: 'node.waypoint',
        style: {
          width: 10,
          height: 10,
          shape: 'ellipse',
          'background-color': 'data(color)',
          'background-opacity': 1,
          'border-width': 2,
          'border-color': '#0E1116',
          'border-style': 'solid',
          label: '',
          'z-index': 2,
        },
      },
      {
        selector: 'node.waypoint:selected',
        style: {
          'border-width': 3,
          'border-color': '#5AA9FF',
        },
      },
    ],
    layout: { name: 'cose', animate: false, randomize: false },
    wheelSensitivity: 0.2,
    minZoom: 0.05,
    maxZoom: 3,
  });

  // Пересчёт точек изломов (NR-035 п.2) и ломаных связей с точками
  // изгиба (NR-038 п.1), шрифт подписей при малом масштабе (NR-038
  // п.3): позиции зависят от положения узлов и масштаба, поэтому
  // пересчитываются на перемещение узлов, зуме и панели — с
  // throttling через requestAnimationFrame.
  let mapSyncScheduled = 0;
  const scheduleMapSync = (): void => {
    if (mapSyncScheduled !== 0) return;
    mapSyncScheduled = requestAnimationFrame(() => {
      mapSyncScheduled = 0;
      syncMap(cy);
    });
  };
  cy.on('position', 'node', (ev: EventObject) => {
    const t = ev.target as NodeSingular;
    if (t.hasClass('bend')) return;
    scheduleMapSync();
  });
  cy.on('pan zoom resize', () => scheduleMapSync());

  // Двойной клик (NR-033 п.3): cytoscape не умеет dblclick — два
  // быстрых tap по одному узлу в пределах 400 мс открывают карточку.
  // Точки изгиба (NR-038 п.1): два tap по точке — удалить её.
  let lastTapId = '';
  let lastTapAt = 0;
  cy.on('tap', 'node', (ev: EventObject) => {
    const n = ev.target as NodeSingular;
    if (n.hasClass(WAYPOINT_CLASS)) {
      const wpId = n.id();
      const now = Date.now();
      if (wpId === lastTapId && now - lastTapAt < 400) {
        lastTapId = '';
        lastTapAt = 0;
        removeWaypoint(cy, n);
      } else {
        lastTapId = wpId;
        lastTapAt = now;
      }
      return;
    }
    const info = nodeInfoOf(n);
    const now = Date.now();
    if (info.id === lastTapId && now - lastTapAt < 400) {
      lastTapId = '';
      lastTapAt = 0;
      cb.onNodeOpen(info);
      return;
    }
    lastTapId = info.id;
    lastTapAt = now;
    cb.onNodeSelect(info);
    cb.onLinkSelect(null, null);
  });
  // Двойной клик по связи (NR-038 п.1): узловая точка в месте клика;
  // одиночный клик — выбор связи. Клик по точке изгиба не мешает:
  // события точек не доходят до ребра (узел перехватывает tap).
  let lastEdgeTapId = '';
  let lastEdgeTapAt = 0;
  cy.on('tap', 'edge', (ev: EventObject) => {
    const e = ev.target;
    const now = Date.now();
    if (e.id() === lastEdgeTapId && now - lastEdgeTapAt < 400) {
      lastEdgeTapId = '';
      lastEdgeTapAt = 0;
      const p = ev.position as Point | undefined;
      if (p !== undefined) addWaypoint(cy, e, p);
      return;
    }
    lastEdgeTapId = e.id();
    lastEdgeTapAt = now;
    cb.onLinkSelect(linkInfoOf(e), e.id());
  });
  cy.on('tap', (ev: EventObject) => {
    if (ev.target === cy) {
      cb.onNodeSelect(null);
      cb.onLinkSelect(null, null);
    }
  });

  // Перетаскивание точки изгиба (NR-038 п.1): линия следует за
  // точкой (rAF-цикл), после отпускания — привязка к мелкой сетке
  // при включённой «Привязке к сетке» и сохранение на сервере.
  cy.on('dragfree', `node.${WAYPOINT_CLASS}`, (ev: EventObject) => {
    const n = ev.target as NodeSingular;
    const snap = document.getElementById('snap-grid') as HTMLInputElement | null;
    moveWaypoint(cy, n, snap === null ? true : snap.checked);
  });

  // Контекстное меню точки изгиба (NR-038 п.1): правый клик —
  // меню «Удалить точку» у курсора.
  setupWaypointMenu(cy);
  setupTooltip(cy, container);
  return cy;
}

// setupWaypointMenu — контекстное меню точки изгиба: правый клик по
// точке открывает меню «Удалить точку»; клик мимо меню закрывает его.
// Ненадёжный текст в DOM не попадает: только статические строки.
function setupWaypointMenu(cy: Core): void {
  const menu = document.getElementById('wp-menu');
  const item = document.getElementById('wp-menu-delete');
  if (menu === null || item === null) return;
  let target: NodeSingular | null = null;
  const hide = (): void => {
    menu.hidden = true;
    target = null;
  };
  cy.on('cxttap', `node.${WAYPOINT_CLASS}`, (ev: EventObject) => {
    target = ev.target as NodeSingular;
    const rect = (cy.container() as HTMLElement).getBoundingClientRect();
    const pos = (ev.target as NodeSingular).renderedPosition();
    menu.style.left = `${Math.min(pos.x + rect.left + 6, Math.max(0, rect.right - 170))}px`;
    menu.style.top = `${Math.min(pos.y + rect.top + 6, Math.max(0, rect.bottom - 60))}px`;
    menu.hidden = false;
  });
  cy.on('drag pan zoom', () => hide());
  item.addEventListener('click', () => {
    if (target !== null) removeWaypoint(cy, target);
    hide();
  });
  document.addEventListener('click', (ev) => {
    if (!menu.hidden && !menu.contains(ev.target as Node)) hide();
  });
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
// GraphStatuses — статусы узлов из сигналов (NR-033 п.4): маркер на
// значке, ободок плашки и счётчик открытых решений.
export interface GraphStatuses {
  status: (id: string) => { status: NodeStatusKind; decisions: number };
}

// SetGraphOptions — варианты перезаливки графа (NR-035 п.1).
export interface SetGraphOptions {
  // rearrange — игнорировать текущие позиции канвы и расставить
  // все узлы сеткой заново: «Выстроить сеткой» стирает сохранённые
  // положения и пересобирает раскладку целиком.
  rearrange?: boolean;
}

export function setGraph(
  cy: Core,
  g: Graph,
  saved?: ReadonlyMap<string, { x: number; y: number }>,
  statuses?: GraphStatuses,
  opts?: SetGraphOptions,
): void {
  const positions = new Map<string, { x: number; y: number }>();
  if (opts?.rearrange !== true) {
    cy.nodes().forEach((n) => {
      if (n.hasClass('bend') || n.hasClass(WAYPOINT_CLASS)) return;
      positions.set(n.id(), n.position());
    });
  }
  cy.elements().remove();

  const elements: ElementDefinition[] = [];
  const placed = new Set<string>();
  let hasGuests = false;
  for (const n of g.nodes) {
    const nodeStatus = statuses?.status(n.id) ?? { status: 'online' as NodeStatusKind, decisions: 0 };
    // Непроверенный узел без более сильного сигнала показывается как
    // ◇ не проверен (NR-033 п.2).
    const status: NodeStatusKind =
      nodeStatus.status === 'online' && !n.verified ? 'unverified' : nodeStatus.status;
    const st = nodeStyle(n, status, nodeStatus.decisions);
    hasGuests = hasGuests || n.class === 'guest';
    if (positions.has(n.id) || saved?.has(n.id)) placed.add(n.id);
    elements.push({
      group: 'nodes',
      data: {
        id: n.id,
        kind: n.kind,
        label: nodeLabel(n),
        fullLabel: n.label || n.id,
        marks: nodeMarks(n).join(', '),
        icon: st.icon,
        border: st.borderColor,
        manual: n.manual,
        verified: n.verified,
        kindLabel: st.kindLabel,
        // NR-036 п.4: в a11y-описании узла — тип и статус.
        aria: `${st.kindLabel}: ${n.label} — ${STATUS_STYLES[status].label}`,
        // Гости объединяются группой «Гостевая сеть» (compound).
        parent: n.class === 'guest' ? 'grp-guest' : undefined,
      },
      // Приоритет положения (NR-035 п.1): текущая позиция на канве
      // (владелец двигал, отправка ещё не прошла) сильнее серверной;
      // серверная — сильнее раскладки; без всего — раскладка.
      position: positions.get(n.id) ?? saved?.get(n.id) ?? { x: 0, y: 0 },
      style: {
        shape: st.shape,
        width: String(st.width),
        height: String(st.height),
        // NR-037 п.1: подпись шлюза — НАД диском. Звезда связей
        // подходит к роутеру снизу, точка соединения — на нижней
        // кромке диска; подпись под диском попадала бы под линию
        // и под точку («у Huawei подпись наезжает на точку и линию»).
        ...(n.kind === 'router'
          ? { 'text-valign': 'top', 'text-margin-y': '-6' }
          : {}),
      },
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
        // Рамка группы — пунктир (граница гостей); у обычных узлов
        // рамки нет (кольцо в SVG, NR-036), группе задаётся явно.
        'border-width': 2,
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
        // Устойчивый ключ связи для точек изгиба (NR-038 п.1):
        // сервер отдаёт «a|aPort|b|bPort» либо «assumed:<id>».
        wpKey: l.wp_key ?? edgeId(l),
      },
    });
  }
  cy.add(elements);
  arrangeMap(cy, g, placed, saved ?? new Map());
  fitIfClipped(cy);
  syncBendDots(cy);
}

// fitIfClipped — если карта не влезает в окно (шлюз у края канвы,
// NR-033 п.1: обзор всей карты), подгоняет масштаб; пока карта видна
// целиком, зум и панорама владельца не трогаются. После подгонки
// значки не мельче 32 px (NR-034 п.2), если карта по ширине всё
// равно влезает: переполнение по высоте допустимо, мельче — нет.
export function fitIfClipped(cy: Core): void {
  if (cy.elements().length === 0) return;
  const bb = cy.elements().boundingBox();
  const ext = cy.extent();
  const inside =
    bb.x1 >= ext.x1 && bb.x2 <= ext.x2 && bb.y1 >= ext.y1 && bb.y2 <= ext.y2;
  if (inside) return;
  cy.fit(cy.elements(), FIT_PADDING);
  if (cy.zoom() >= MIN_ICON_ZOOM) return;
  // Ширина карты при минимальном зуме влезает в канву с полями —
  // поднимаем зум: по высоте карта прокручивается, значки читаются.
  const width = bb.x2 - bb.x1;
  if (width * MIN_ICON_ZOOM <= cy.width() - FIT_PADDING) {
    cy.zoom(MIN_ICON_ZOOM);
    cy.center(cy.elements());
  }
}

// arrangeMap — детерминированная раскладка (NR-032 п.4): позиции
// узлов без сохранённого смещения — из arrangeGrid (шлюз сверху,
// ряды по типам); затем deoverlap для защиты от пересечений, если
// сохранённые позиции влезли в сетку.
function arrangeMap(
  cy: Core,
  g: Graph,
  placed: ReadonlySet<string>,
  saved: ReadonlyMap<string, { x: number; y: number }>,
): void {
  const nodeEls: NodeSingular[] = [];
  cy.nodes().forEach((n) => {
    if (!n.isParent() && !n.hasClass('bend') && !n.hasClass(WAYPOINT_CLASS)) nodeEls.push(n);
  });
  // Расставляются узлы БЕЗ явного положения (placed — узлы с
  // положением: текущим на канве или серверным, NR-035 п.1).
  const arranging = nodeEls.filter((n) => !placed.has(n.id()));
  if (arranging.length === 0) return;
  const kinds = new Map(g.nodes.map((n) => [n.id, n.kind]));
  // Ширина области карты в модельных координатах при масштабе по
  // умолчанию (NR-034 п.2): ряд переносится, когда не влезает.
  const maxWidth = Math.max(400, (cy.width() - FIT_PADDING) / MIN_ICON_ZOOM);
  const grid = arrangeGrid(
    arranging.map((n) => ({
      id: n.id(),
      kind: kinds.get(n.id()) ?? 'unknown',
      label: String(n.data('label') ?? ''),
    })),
    saved,
    maxWidth,
  );
  for (const n of arranging) {
    const p = grid.get(n.id());
    if (p !== undefined) n.position({ x: p.x, y: p.y });
  }
  // Пересечения разводятся только среди автоматически расставленных:
  // узлы владельца не сдвигаются.
  const auto: Positioned[] = arranging
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
    .filter((n) => placed.has(n.id()))
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

// syncMap — перерисовка производных элементов карты: точки изгиба
// подтягиваются из перетаскиваемых узлов, ломаные связей
// пересчитываются, автоматические точки изломов следуют за
// сегментами, шрифт подписей догоняется до экранных минимумов.
export function syncMap(cy: Core): void {
  syncWaypointNodes(cy);
  recomputeWaypointEdges(cy);
  syncBendDots(cy);
  syncLabelZoom(cy);
}

// lastLabelZoom — масштаб, при котором шрифт подписей применён
// последний раз (WeakMap: карт на странице может быть несколько).
const lastLabelZoom = new WeakMap<Core, number>();

// syncLabelZoom — шрифт подписей при малом масштабе (NR-038 п.3):
// ниже 0.7 шрифт в модельных единицах растёт так, чтобы на экране
// подпись была не мельче 11 px; выше — базовые 13 px (стиль узла).
export function syncLabelZoom(cy: Core, force = false): void {
  const z = cy.zoom();
  if (!force && lastLabelZoom.get(cy) === z) return;
  lastLabelZoom.set(cy, z);
  const fs =
    z >= LABEL_MIN_SCREEN_ZOOM
      ? LABEL_FONT_SIZE
      : Math.round((LABEL_MIN_SCREEN_SIZE / z) * 100) / 100;
  cy.nodes()
    .filter((n) => !n.hasClass('bend') && !n.hasClass(WAYPOINT_CLASS) && !n.isParent())
    .style('font-size', fs);
}

// syncBendDots — точки на изломах и концах ортогональных линий
// (NR-035 п.2, NR-037 п.1): порт-узел в каждой сегментной точке ребра
// и на стыке линии с диском узла (sourceEndpoint/targetEndpoint —
// верх диска у устройства, низ у шлюза), цветом линии. Позиции
// пересчитываются при перемещении узлов и смене масштаба; устаревшие
// точки удаляются. Точки не попадают в раскладку, не ловят события
// и рисуются ниже узлов и подписей (z-index: -1). Пользовательские
// точки изгиба (NR-038 п.1) рисуются отдельно — на их местах
// автоматические точки не ставятся.
export function syncBendDots(cy: Core): void {
  const userPoints: { x: number; y: number }[] = [];
  cy.nodes(`.${WAYPOINT_CLASS}`).forEach((n) => {
    userPoints.push(n.position());
  });
  const atWaypoint = (p: { x: number; y: number }): boolean =>
    userPoints.some((w) => Math.abs(w.x - p.x) < 1 && Math.abs(w.y - p.y) < 1);
  const seen = new Set<string>();
  cy.edges().forEach((e) => {
    // Точки изломов нумеруются по индексу сегментной точки; точки на
    // стыках с дисками имеют явные суффиксы src/tgt — число изломов
    // может меняться при перемещении узлов, стыки — стабильны.
    const places: { suffix: string; p: { x: number; y: number } }[] = [];
    const segs = e.segmentPoints() as { x: number; y: number }[];
    for (let i = 0; i < segs.length; i++) {
      const p = segs[i];
      if (p !== undefined) places.push({ suffix: String(i), p });
    }
    places.push(
      { suffix: 'src', p: e.sourceEndpoint() as { x: number; y: number } },
      { suffix: 'tgt', p: e.targetEndpoint() as { x: number; y: number } },
    );
    for (const { suffix, p } of places) {
      if (p === undefined || atWaypoint(p)) continue;
      const id = `bend:${e.id()}:${suffix}`;
      seen.add(id);
      const existing = cy.$id(id).first() as NodeSingular | undefined;
      if (existing !== undefined && existing.nonempty()) {
        existing.position({ x: p.x, y: p.y });
      } else {
        cy.add({
          group: 'nodes',
          data: { id, color: String(e.data('color') ?? '#7C8798') },
          position: { x: p.x, y: p.y },
          classes: 'bend',
        });
      }
    }
  });
  cy.nodes()
    .filter((n) => n.hasClass('bend') && !seen.has(n.id()))
    .remove();
}

// fitMap — кнопка «Вписать в окно» (NR-035 п.3): вся карта видима.
export function fitMap(cy: Core): void {
  if (cy.elements().length === 0) return;
  cy.fit(cy.elements(), FIT_PADDING);
}

// centerMap — кнопка «Центр» (NR-035 п.3): центрирование без смены
// масштаба.
export function centerMap(cy: Core): void {
  if (cy.elements().length === 0) return;
  cy.center(cy.elements());
}

// zoom100 — кнопка «100%» (NR-035 п.3): масштаб 1:1, содержимое в
// центре канвы.
export function zoom100(cy: Core): void {
  if (cy.elements().length === 0) return;
  cy.zoom(1);
  cy.center(cy.elements());
}

// Поле от угла канвы при показе верхнего левого фрагмента (NR-035 п.3).
const CORNER_PAD = 40;

// initialFit — первая загрузка карты (NR-035 п.3): вписать в окно,
// но значки не мельче 32 px (MIN_ICON_ZOOM, NR-034 п.2); если карта
// целиком не помещается, показывается верхний левый фрагмент — поле
// двигается перетаскиванием и клавишами.
export function initialFit(cy: Core): void {
  if (cy.nodes().length === 0) return;
  cy.fit(cy.elements(), FIT_PADDING);
  if (cy.zoom() >= MIN_ICON_ZOOM) return;
  cy.zoom(MIN_ICON_ZOOM);
  const bb = cy.elements().boundingBox();
  cy.pan({
    x: CORNER_PAD - bb.x1 * MIN_ICON_ZOOM,
    y: CORNER_PAD - bb.y1 * MIN_ICON_ZOOM,
  });
}

// renderA11y — скрытый список узлов для скринридеров и сквозных
// тестов (NR-032 п.6): каждый узел — строка с data-kind, типом и
// статусом (NR-033 п.4).
export function renderA11y(g: Graph, statuses?: GraphStatuses): void {
  const box = document.getElementById('map-a11y');
  if (box === null) return;
  box.textContent = '';
  for (const n of g.nodes) {
    const li = document.createElement('li');
    li.dataset.kind = n.kind;
    li.dataset.id = n.id;
    const nodeStatus = statuses?.status(n.id) ?? { status: 'online' as NodeStatusKind, decisions: 0 };
    const status: NodeStatusKind =
      nodeStatus.status === 'online' && !n.verified ? 'unverified' : nodeStatus.status;
    const st = nodeStyle(n);
    const glyph = STATUS_STYLES[status]?.glyph ?? '';
    const label = STATUS_STYLES[status]?.label ?? '';
    li.textContent = `${n.label} — ${st.kindLabel} — ${glyph} ${label}`;
    box.append(li);
  }
}

// nodeLabel — короткая подпись узла (NR-038 п.3): перенос по словам
// не длиннее двух строк, «…» не режет слово посередине; полный текст
// остаётся в data(fullLabel) для подсказки. «не проверен» в подпись
// не попадает (маркер на узле).
function nodeLabel(n: NodeInfo): string {
  const base = wrapLabel(n.label || n.id);
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
