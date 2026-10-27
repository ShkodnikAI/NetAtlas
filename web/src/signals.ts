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

// AttentionPanelHandlers — клик по строке фокусирует узел.
export interface AttentionPanelHandlers {
  onFocus: (deviceId: string) => void;
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
// устройства (журнал аудита) — без фокуса. Повторный вызов
// перезаливает содержимое.
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
  for (const s of sorted) {
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
    container.append(row);
  }
}
