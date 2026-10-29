// Сигналы внимания на карте (NR-033 п.4): сводный статус узла из
// сигналов, сортировка панели «Требуют внимания» по важности,
// отрисовка панели. Все строки из API недоверенные — только
// textContent. Сигналы считаются сервером из уже собранных данных,
// сеть интерфейс не расходует.

import type { MapSignal, NodeInfo, SignalsView } from './api';
import { STATUS_STYLES, svgIcon, type NodeStatusKind } from './nodes';

// Порядок важности статусов сигнала.
const SIGNAL_RANK: Record<string, number> = { problem: 0, attention: 1, offline: 2 };

// sortSignals — по убыванию важности: ■ с решением, ■, ▲ с
// решением, ▲, ○; внутри группы — по тексту (детерминированно).
export function sortSignals(signals: MapSignal[]): MapSignal[] {
  return [...signals].sort((a, b) => {
    const da = a.decision ? 0 : 1;
    const db = b.decision ? 0 : 1;
    const ra = SIGNAL_RANK[a.status] ?? 3;
    const rb = SIGNAL_RANK[b.status] ?? 3;
    if (ra !== rb) return ra - rb;
    if (da !== db) return da - db;
    return a.text.localeCompare(b.text, 'ru');
  });
}

// SignalStatus — статус узла для значка: маркер и счётчик решений.
export interface SignalStatus {
  status: NodeStatusKind;
  decisions: number;
}

// statusesOf — сводный статус каждого узла из ответа /api/signals:
// ■ проблема > ▲ внимание > ○ не в сети > ◇ не проверен > ● в сети.
// «◇ не проверен» подставляет вызывающий (у него есть node.verified).
export function statusesOf(view: SignalsView): Map<string, SignalStatus> {
  const out = new Map<string, SignalStatus>();
  for (const st of view.statuses) {
    out.set(st.id, { status: st.status, decisions: st.decisions });
  }
  return out;
}

// deviceLabel — подпись устройства для панели (или сам id).
function deviceLabel(id: string, nodes: NodeInfo[]): string {
  const n = nodes.find((x) => x.id === id);
  return n ? n.label || n.id : id;
}

// AttentionPanelHandlers — клик по строке фокусирует узел;
// onAcceptAll (NR-037 п.5) принимает всю группу новых устройств
// одним классом («Моё»/«Гость»).
export interface AttentionPanelHandlers {
  onFocus: (deviceId: string) => void;
  // NR-037 п.5: принять все новые устройства группы одним классом.
  onAcceptAll?: (deviceIds: string[], klass: string) => void;
}

// SIGNAL_HEAD — короткая шапка сигнала по виду (kind).
const SIGNAL_HEAD: Record<string, string> = {
  unknown_new: 'Новое устройство',
  no_response: 'Не в сети',
  security: 'Безопасность',
  quality: 'Качество сети',
  eol: 'Поддержка ОС',
  ip_conflict: 'Повтор адреса',
  audit_gap: 'Журнал аудита',
};

// renderAttentionPanel — панель «Требуют внимания»: список сигналов
// по убыванию важности; строка показывает маркер статуса, значок
// роли устройства (NR-036 п.1), шапку и текст. Сигналы без
// устройства (журнал аудита) — без фокуса. NR-037 п.5: однотипные
// сигналы «новое устройство» (решение владельца) сворачиваются в
// одну строку «Новые устройства: N» с раскрытием и приёмом всей
// группы одним классом; на узле остаётся маркер ▲, но счётчик «1»
// при одинаковой причине не повторяется (withGroupedDecisions).
// Повторный вызов перезаливает содержимое.
export function renderAttentionPanel(
  container: HTMLElement,
  signals: MapSignal[],
  nodes: NodeInfo[],
  handlers: AttentionPanelHandlers,
): void {
  container.textContent = '';
  const sorted = sortSignals(signals);
  if (sorted.length === 0) {
    container.hidden = true;
    return;
  }
  container.hidden = false;
  const { group, rest } = newDeviceGroup(signals);
  const groupedIds = new Set(group.map((s) => s.device_id));
  // Позиция группы — место первого её сигнала в общей сортировке:
  // группа идёт после проблем и перед остальными строками.
  let groupShown = false;
  for (const s of sorted) {
    if (!groupShown && groupedIds.has(s.device_id)) {
      container.append(groupBlock(group, nodes, handlers));
      groupShown = true;
    }
    if (groupedIds.has(s.device_id)) continue;
    container.append(signalRow(s, nodes, handlers));
  }
  if (!groupShown && group.length >= 2) {
    container.append(groupBlock(group, nodes, handlers));
  }
  void rest;
}

// signalRow — одна строка панели: маркер, значок роли, шапка, текст.
function signalRow(
  s: MapSignal,
  nodes: NodeInfo[],
  handlers: AttentionPanelHandlers,
): HTMLButtonElement {
  const row = document.createElement('button');
  row.type = 'button';
  row.className = `attention-row status-${s.status}`;
  row.dataset.deviceId = s.device_id;
  row.dataset.kind = s.kind;
  if (s.device_id === '') row.disabled = true;
  const mark = document.createElement('span');
  mark.className = 'attention-mark';
  mark.textContent = STATUS_STYLES[s.status as NodeStatusKind]?.glyph ?? '●';
  mark.setAttribute('aria-hidden', 'true');
  row.append(mark);
  // NR-036 п.1: значок роли устройства (статическая таблица
  // типов, не данные API) — рядом с текстом сигнала.
  const node = nodes.find((x) => x.id === s.device_id);
  if (node !== undefined) {
    const icon = document.createElement('img');
    icon.src = svgIcon(node.kind);
    icon.alt = '';
    icon.width = 20;
    icon.height = 20;
    icon.className = 'attention-icon';
    row.append(icon);
  }
  const body = document.createElement('span');
  body.className = 'attention-body';
  const head = document.createElement('span');
  head.className = 'attention-head';
  head.textContent =
    (SIGNAL_HEAD[s.kind] ?? s.kind) +
    (s.device_id !== '' ? `: ${deviceLabel(s.device_id, nodes)}` : '');
  const text = document.createElement('span');
  text.className = 'attention-text';
  text.textContent = s.text;
  body.append(head, text);
  row.append(mark, body);
  if (s.device_id !== '') {
    row.addEventListener('click', () => handlers.onFocus(s.device_id));
  }
  return row;
}

// ACCEPT_ALL_CLASSES — классы приёма группы новых устройств
// (NR-037 п.5): «Моё» и «Гость», как в таблице устройств.
const ACCEPT_ALL_CLASSES: [string, string][] = [
  ['managed', 'Моё'],
  ['guest', 'Гость'],
];

// groupBlock — свёрнутая группа однотипных сигналов «новое
// устройство» (NR-037 п.5): одна строка «Новые устройства: N»,
// раскрытие показывает отдельные сигналы, кнопки принимают всю
// группу одним классом. Раскрытие — на владельце, приём — по клику.
function groupBlock(
  group: MapSignal[],
  nodes: NodeInfo[],
  handlers: AttentionPanelHandlers,
): HTMLDivElement {
  const box = document.createElement('div');
  box.className = 'attention-group';
  box.dataset.kind = 'unknown_new';
  const head = document.createElement('button');
  head.type = 'button';
  head.className = 'attention-row status-attention attention-group-head';
  head.setAttribute('aria-expanded', 'false');
  const mark = document.createElement('span');
  mark.className = 'attention-mark';
  mark.textContent = STATUS_STYLES['attention'].glyph;
  mark.setAttribute('aria-hidden', 'true');
  const body = document.createElement('span');
  body.className = 'attention-body';
  const headText = document.createElement('span');
  headText.className = 'attention-head';
  headText.textContent = `Новые устройства: ${group.length}`;
  const sub = document.createElement('span');
  sub.className = 'attention-text';
  sub.textContent = 'принять все как «Моё» или «Гость» — решение одно на всех';
  body.append(headText, sub);
  const toggle = document.createElement('span');
  toggle.className = 'attention-toggle';
  toggle.textContent = '▸';
  toggle.setAttribute('aria-hidden', 'true');
  head.append(mark, body, toggle);
  const actions = document.createElement('div');
  actions.className = 'attention-group-actions';
  actions.hidden = true;
  const list = document.createElement('div');
  list.className = 'attention-group-list';
  list.hidden = true;
  for (const [klass, label] of ACCEPT_ALL_CLASSES) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'attention-accept';
    b.textContent = `Принять все как ${label}`;
    b.addEventListener('click', () =>
      handlers.onAcceptAll?.(
        group.map((s) => s.device_id),
        klass,
      ),
    );
    actions.append(b);
  }
  for (const s of group) {
    list.append(signalRow(s, nodes, handlers));
  }
  head.addEventListener('click', () => {
    const open = head.getAttribute('aria-expanded') === 'true';
    head.setAttribute('aria-expanded', open ? 'false' : 'true');
    actions.hidden = open;
    list.hidden = open;
    toggle.textContent = open ? '▸' : '▾';
  });
  box.append(head, actions, list);
  return box;
}

// newDeviceGroup — группа однотипных сигналов «новое устройство»
// (NR-037 п.5): сигналы с решением владельца об одном и том же —
// приём нового устройства. Группа имеет смысл от двух сигналов;
// одиночный сигнал остаётся отдельной строкой.
export function newDeviceGroup(signals: MapSignal[]): {
  group: MapSignal[];
  rest: MapSignal[];
} {
  const group = signals.filter(
    (s) => s.kind === 'unknown_new' && s.decision && s.device_id !== '',
  );
  if (group.length < 2) return { group: [], rest: signals };
  const ids = new Set(group.map((s) => s.device_id));
  return { group, rest: signals.filter((s) => !ids.has(s.device_id)) };
}

// attentionBadgeCount — счётчик на кнопке «Требуют внимания»
// (NR-037 п.5): группа однотипных сигналов считается одним сигналом.
export function attentionBadgeCount(signals: MapSignal[]): number {
  const { group } = newDeviceGroup(signals);
  return signals.length - group.length + (group.length >= 2 ? 1 : 0);
}

// withGroupedDecisions — сводный статус узлов для значков
// (NR-037 п.5): у узлов, чьи открытые решения — только сгруппированные
// «новые устройства», счётчик решений на значке не показывается
// (маркер ▲ остаётся: статус не меняется). Узел с другим решением
// или сигналом показывает настоящий счётчик.
export function withGroupedDecisions(
  statuses: Map<string, SignalStatus>,
  signals: MapSignal[],
): Map<string, SignalStatus> {
  const { group } = newDeviceGroup(signals);
  if (group.length < 2) return statuses;
  const grouped = new Set(group.map((s) => s.device_id));
  const otherDecisions = new Set(
    signals
      .filter((s) => s.decision && s.kind !== 'unknown_new' && s.device_id !== '')
      .map((s) => s.device_id),
  );
  const out = new Map<string, SignalStatus>();
  for (const [id, st] of statuses) {
    out.set(
      id,
      grouped.has(id) && !otherDecisions.has(id)
        ? { status: st.status, decisions: 0 }
        : st,
    );
  }
  return out;
}
