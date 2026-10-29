// Полная карточка устройства (NR-033 п.3): двойной клик по узлу
// открывает экран со всей информацией — имена и источники, MAC, IP,
// производитель, тип, класс, обнаружения, наблюдения, открытые
// порты, данные агента, «Найдено правилами», качество, привязанный
// пользователь, оповещения, история изменений и действия. Одинарный
// клик остаётся быстрой боковой панелью. Все данные из API
// недоверенные: вставка только через textContent.

import type { DeviceInfo, Graph, MapSignal } from './api';
import { className, CLASSES, KIND_OPTIONS, kindIcon } from './panels';
import { displayName } from './scan';
import { KIND_LABELS } from './nodes';

export interface CardHandlers {
  onClose: () => void;
  onClass: (id: string, klass: string) => void;
  onKind: (id: string, kind: string) => void;
  onVerify: (id: string) => void;
  // Соединить: первый узел пары уже выбран (этот).
  onConnect: (id: string) => void;
  // Разорвать ручную связь устройства (если есть).
  onDisconnect: (id: string) => void;
  onDelete: (id: string) => void;
  // Решение по сигналу «новое устройство».
  onAccept: (id: string, klass: string) => void;
  // Игнорировать сигнал на N дней.
  onSnooze: (id: string, kind: string, days: number) => void;
  // Сформировать отчёт для ИИ.
  onReport: (id: string, agentID: string, label: string) => void;
}

// Вкладки карточки: id вкладки → id страницы.
const CARD_TABS: [string, string][] = [
  ['card-tab-overview', 'card-page-overview'],
  ['card-tab-agent', 'card-page-agent'],
  ['card-tab-ports', 'card-page-ports'],
  ['card-tab-security', 'card-page-security'],
  ['card-tab-quality', 'card-page-quality'],
  ['card-tab-decisions', 'card-page-decisions'],
  ['card-tab-links', 'card-page-links'],
  ['card-tab-history', 'card-page-history'],
];

function el(tag: string, className?: string): HTMLElement {
  const e = document.createElement(tag);
  if (className) e.className = className;
  return e;
}

function text(parent: HTMLElement, value: string): void {
  parent.textContent = value;
}

// kvRow — строка «термин — значение».
function kvRow(dl: HTMLElement, term: string, value: string): void {
  const dt = el('dt');
  text(dt, term);
  const dd = el('dd');
  text(dd, value);
  dl.append(dt, dd);
}

// fmtTime — время в местном виде для карточки.
function fmtTime(iso?: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString('ru-RU');
}

// selectCardTab — переключение вкладок карточки.
export function selectCardTab(tabId: string): void {
  for (const [tab, page] of CARD_TABS) {
    const tabEl = document.getElementById(tab);
    const pageEl = document.getElementById(page);
    if (tabEl === null || pageEl === null) continue;
    tabEl.setAttribute('aria-selected', tab === tabId ? 'true' : 'false');
    pageEl.classList.toggle('active', tab === tabId);
  }
}

// fillCard — заливает экран «Карточка устройства» данными.
// decisions — открытые решения устройства (сигналы с decision).
// hasManualLink — есть ли ручная связь для разрыва.
export function fillCard(
  root: HTMLElement,
  info: DeviceInfo,
  graph: Graph,
  decisions: MapSignal[],
  hasManualLink: boolean,
  handlers: CardHandlers,
): void {
  root.textContent = '';

  // Шапка: имя, метки, кнопка назад.
  const head = el('div', 'card-head');
  const title = el('h2');
  // hostname может отсутствовать в ответе (omitempty): undefined
  // превращается в пустую строку. NR-037 п.3: имя карточки — то же,
  // что в таблице и на карте: у шлюза без имени — «Роутер <IP>».
  text(title, info.hostname ? info.hostname : displayName(info));
  const marks = el('p', 'card-marks');
  const badge = (cls: string, label: string): void => {
    const b = el('span', `badge ${cls}`);
    text(b, label);
    marks.append(b, document.createTextNode(' '));
  };
  if (info.manual) badge('manual', 'вручную');
  if (!info.verified) badge('unverified', 'не проверен');
  if (info.alerts && info.alerts.length > 0) badge('manual', 'новое устройство');
  head.append(title, marks);
  const back = el('button', 'card-back') as HTMLButtonElement;
  back.type = 'button';
  text(back, '← На карту');
  back.addEventListener('click', handlers.onClose);
  head.append(back);
  root.append(head);

  // Действия: сменить класс или тип, проверить, соединить, разорвать,
  // удалить, отчёт для ИИ (NR-033 п.3).
  const actions = el('div', 'card-actions');

  const classSel = el('select') as HTMLSelectElement;
  classSel.id = 'card-class';
  for (const [value, label] of CLASSES) {
    const opt = document.createElement('option');
    opt.value = value;
    text(opt, label);
    if (value === info.class) opt.selected = true;
    classSel.append(opt);
  }
  const classApply = el('button') as HTMLButtonElement;
  classApply.type = 'button';
  text(classApply, 'Сменить класс');
  classApply.addEventListener('click', () => handlers.onClass(info.id, classSel.value));
  actions.append(classSel, classApply);

  const kindSel = el('select') as HTMLSelectElement;
  kindSel.id = 'card-kind';
  for (const [value, label] of KIND_OPTIONS) {
    const opt = document.createElement('option');
    opt.value = value;
    text(opt, label);
    if (value === (info.kind ?? '')) opt.selected = true;
    kindSel.append(opt);
  }
  const kindApply = el('button') as HTMLButtonElement;
  kindApply.type = 'button';
  text(kindApply, 'Сменить тип');
  kindApply.addEventListener('click', () => handlers.onKind(info.id, kindSel.value));
  actions.append(kindSel, kindApply);

  const verify = el('button') as HTMLButtonElement;
  verify.type = 'button';
  text(verify, 'Проверить (ping)');
  verify.addEventListener('click', () => handlers.onVerify(info.id));
  const connect = el('button') as HTMLButtonElement;
  connect.type = 'button';
  text(connect, 'Соединить');
  connect.addEventListener('click', () => handlers.onConnect(info.id));
  const disconnect = el('button') as HTMLButtonElement;
  disconnect.type = 'button';
  text(disconnect, 'Разорвать связь');
  disconnect.disabled = !hasManualLink;
  disconnect.title = hasManualLink
    ? 'Разрывает ручную связь устройства'
    : 'Ручных связей у устройства нет — разрывать нечего';
  disconnect.addEventListener('click', () => handlers.onDisconnect(info.id));
  actions.append(verify, connect, disconnect);

  if (info.manual) {
    const del = el('button') as HTMLButtonElement;
    del.type = 'button';
    text(del, 'Удалить ручной элемент');
    del.addEventListener('click', () => handlers.onDelete(info.id));
    actions.append(del);
  }

  const report = el('button') as HTMLButtonElement;
  report.type = 'button';
  text(report, 'Сформировать отчёт для ИИ');
  report.addEventListener('click', () => handlers.onReport(info.id, info.agent?.id ?? '', info.hostname || info.id));
  actions.append(report);
  root.append(actions);

  const verdict = el('div', 'verdict');
  verdict.id = 'card-verdict';
  root.append(verdict);

  // Вкладки.
  const tabs = el('div', 'tabs');
  tabs.setAttribute('role', 'tablist');
  tabs.setAttribute('aria-label', 'Вкладки карточки');
  const tabLabels: Record<string, string> = {
    'card-tab-overview': 'Обзор',
    'card-tab-agent': 'Агент',
    'card-tab-ports': 'Порты',
    'card-tab-security': 'Безопасность',
    'card-tab-quality': 'Качество',
    'card-tab-decisions': 'Решения',
    'card-tab-links': 'Связи',
    'card-tab-history': 'История',
  };
  for (const [tab, label] of Object.entries(tabLabels)) {
    const b = el('button') as HTMLButtonElement;
    b.type = 'button';
    b.id = tab;
    b.setAttribute('role', 'tab');
    b.setAttribute('aria-selected', tab === 'card-tab-overview' ? 'true' : 'false');
    b.setAttribute('aria-controls', CARD_TABS.find(([t]) => t === tab)?.[1] ?? '');
    text(b, label);
    b.addEventListener('click', () => selectCardTab(tab));
    tabs.append(b);
  }
  root.append(tabs);

  fillOverview(info);
  fillAgent(info);
  fillPorts(info);
  fillSecurity(info);
  fillQuality(info);
  fillDecisions(info, decisions, handlers);
  fillLinks(info, graph, handlers);
  fillHistory(info);

  // Страницы уже в DOM (index.html); активируем первую вкладку.
  selectCardTab('card-tab-overview');
}

// emptyNote — заметка «данных нет».
function emptyNote(page: HTMLElement, message: string): void {
  const p = el('p', 'muted');
  text(p, message);
  page.append(p);
}

// fillOverview — вкладка «Обзор»: вся идентификация устройства.
function fillOverview(info: DeviceInfo): void {
  const page = document.getElementById('card-page-overview');
  if (page === null) return;
  page.textContent = '';
  const dl = el('dl', 'kv');
  kvRow(dl, 'ID (MAC)', info.id);
  if (info.hostname) kvRow(dl, 'Имя', info.hostname);
  kvRow(dl, 'IP', info.ips.length > 0 ? info.ips.join(', ') : '—');
  if (info.vendor !== '') kvRow(dl, 'Производитель', info.vendor);
  const kindLabel = KIND_LABELS[info.kind ?? ''] ?? 'неизвестное устройство';
  let typeValue = kindLabel;
  if (info.kindManual) typeValue += ' (указан вручную)';
  else if (info.kindAuto !== '' && info.kindAuto === info.kind) typeValue += ' (определён автоматически)';
  // NR-036 п.1: в карточке тип показывается со значком роли; значок
  // строится из статической таблицы типов, текст — через textContent.
  const typeRow = el('div', 'kv-row');
  const typeDt = el('dt');
  text(typeDt, 'Тип');
  const typeDd = el('dd');
  typeDd.append(kindIcon(info.kind ?? 'unknown'), document.createTextNode(typeValue));
  typeRow.append(typeDt, typeDd);
  dl.append(typeRow);
  kvRow(dl, 'Класс', className(info.class));
  if (info.ssid !== '') kvRow(dl, 'SSID', info.ssid);
  kvRow(dl, 'Первое обнаружение', fmtTime(info.first_seen));
  kvRow(dl, 'Последнее обнаружение', fmtTime(info.last_seen));
  if (info.user !== undefined && info.user !== '') kvRow(dl, 'Пользователь', info.user);
  page.append(dl);

  // Имена и источники.
  if (info.names.length > 0) {
    const h = el('h3');
    text(h, 'Имена и источники');
    const ul = el('ul');
    for (const nm of info.names) {
      const li = el('li');
      text(li, `${nm.name} (${nm.source}) — ${fmtTime(nm.seen)}`);
      ul.append(li);
    }
    page.append(h, ul);
  }
  // Наблюдения по источникам.
  const h2 = el('h3');
  text(h2, 'Наблюдения по источникам');
  const ul2 = el('ul');
  for (const o of info.observations) {
    const li = el('li');
    text(li, `${o.source} — ${fmtTime(o.seen)}`);
    ul2.append(li);
  }
  if (ul2.childNodes.length === 0) {
    const li = el('li');
    text(li, 'пока нет наблюдений');
    ul2.append(li);
  }
  page.append(h2, ul2);
}

// fillAgent — вкладка «Агент»: ОС, железо, ПО, диски, обновления.
function fillAgent(info: DeviceInfo): void {
  const page = document.getElementById('card-page-agent');
  if (page === null) return;
  page.textContent = '';
  if (info.agent === undefined) {
    emptyNote(page, 'Агент не привязан: данных о системе нет. Установите агент на этот компьютер.');
    return;
  }
  const dl = el('dl', 'kv');
  kvRow(dl, 'Агент', info.agent.hostname !== undefined && info.agent.hostname !== '' ? info.agent.hostname : info.agent.id);
  kvRow(dl, 'Инвентаризация', fmtTime(info.inventory_at));
  page.append(dl);

  const inv = info.agent_inventory;
  if (inv === undefined) {
    emptyNote(page, 'Инвентаризация ещё не выполнялась.');
    return;
  }
  if (inv.os !== undefined) {
    const h = el('h3');
    text(h, 'Операционная система');
    const dlOs = el('dl', 'kv');
    kvRow(dlOs, 'Система', inv.os.caption ?? '—');
    const verParts = [inv.os.version, inv.os.build_number].filter((x): x is string => x !== undefined && x !== '');
    kvRow(dlOs, 'Версия', verParts.length > 1 ? `${verParts[0]} (${verParts.slice(1).join(', ')})` : verParts[0] ?? '—');
    kvRow(dlOs, 'Архитектура', inv.os.architecture ?? '—');
    kvRow(dlOs, 'Последнее обновление', inv.os.latest_hotfix ?? '—');
    page.append(h, dlOs);
    if (inv.os.hotfixes !== undefined && inv.os.hotfixes.length > 0) {
      const p = el('p', 'muted');
      text(p, `Обновлений в истории: ${inv.os.hotfixes.length}`);
      page.append(p);
    }
  }
  if (inv.hardware !== undefined) {
    const h = el('h3');
    text(h, 'Железо');
    const dlHw = el('dl', 'kv');
    const cpus = inv.hardware.cpus ?? [];
    kvRow(dlHw, 'Процессор', cpus.map((c) => c.name ?? '').filter(Boolean).join(', ') || '—');
    kvRow(dlHw, 'Память', inv.hardware.total_physical_memory ?? '—');
    if (inv.hardware.base_board !== undefined) {
      kvRow(dlHw, 'Плата', [inv.hardware.base_board.manufacturer, inv.hardware.base_board.product].filter(Boolean).join(' '));
    }
    page.append(h, dlHw);
  }
  if (inv.disks !== undefined) {
    const h = el('h3');
    text(h, 'Диски');
    const ul = el('ul');
    for (const d of inv.disks.disks ?? []) {
      const li = el('li');
      text(li, [d.friendly_name, d.media_type, d.size, d.health].filter(Boolean).join(', '));
      ul.append(li);
    }
    for (const v of inv.disks.volumes ?? []) {
      const li = el('li');
      text(li, `Том ${v.drive_letter ?? ''} ${v.file_system ?? ''}: занято ${v.size_remaining ? '' : ''}${v.size ?? ''}`.trim());
      ul.append(li);
    }
    page.append(h, ul);
  }
  if (inv.programs !== undefined && inv.programs.length > 0) {
    const h = el('h3');
    text(h, `Установленное ПО (${inv.programs.length})`);
    const ul = el('ul');
    for (const p of inv.programs.slice(0, 20)) {
      const li = el('li');
      text(li, [p.name, p.version, p.publisher].filter(Boolean).join(', '));
      ul.append(li);
    }
    if (inv.programs.length > 20) {
      const li = el('li');
      text(li, `…и ещё ${inv.programs.length - 20}`);
      ul.append(li);
    }
    page.append(h, ul);
  }
  if (inv.collector_errors !== undefined && inv.collector_errors.length > 0) {
    const h = el('h3');
    text(h, 'Ошибки сборщика');
    const ul = el('ul');
    for (const e of inv.collector_errors) {
      const li = el('li');
      text(li, e);
      ul.append(li);
    }
    page.append(h, ul);
  }
}

// fillPorts — вкладка «Порты»: открытые порты и службы.
function fillPorts(info: DeviceInfo): void {
  const page = document.getElementById('card-page-ports');
  if (page === null) return;
  page.textContent = '';
  if (info.agent === undefined) {
    emptyNote(page, 'Порты видны только с агентом: проверка портов выполняется внутри компьютера.');
    return;
  }
  if (info.ports === undefined || info.ports.length === 0) {
    emptyNote(page, 'Слушающих портов не найдено или проверка ещё не выполнялась.');
    return;
  }
  const ul = el('ul');
  for (const p of info.ports) {
    const li = el('li');
    text(li, `${p.local_address}:${p.local_port}${p.process ? ` — ${p.process}` : ''}`);
    ul.append(li);
  }
  page.append(ul);
}

// fillSecurity — вкладка «Безопасность»: «Найдено правилами».
function fillSecurity(info: DeviceInfo): void {
  const page = document.getElementById('card-page-security');
  if (page === null) return;
  page.textContent = '';
  const h = el('h3');
  text(h, 'Найдено правилами');
  page.append(h);
  if (info.security === undefined || info.security.length === 0) {
    emptyNote(page, 'Находок нет или агент не привязан.');
    return;
  }
  const ul = el('ul', 'findings');
  for (const f of info.security) {
    const li = el('li', `finding severity-${f.severity}`);
    const head = el('span', 'finding-head');
    text(head, `[${f.severity}] ${f.fact}`);
    const advice = el('span', 'finding-advice');
    text(advice, f.advice);
    li.append(head, advice);
    if (f.basis !== '') {
      const basis = el('span', 'finding-basis');
      text(basis, `Основание: ${f.basis}`);
      li.append(basis);
    }
    ul.append(li);
  }
  page.append(ul);
}

// fillQuality — вкладка «Качество»: находки правил по метрикам.
function fillQuality(info: DeviceInfo): void {
  const page = document.getElementById('card-page-quality');
  if (page === null) return;
  page.textContent = '';
  if (info.quality === undefined || info.quality.length === 0) {
    emptyNote(page, 'Замечаний по качеству сети нет или метрик ещё нет.');
    return;
  }
  const ul = el('ul', 'findings');
  for (const f of info.quality) {
    const li = el('li', `finding severity-${f.severity}`);
    const head = el('span', 'finding-head');
    text(head, `[${f.severity}] ${f.fact}`);
    const advice = el('span', 'finding-advice');
    text(advice, f.advice);
    li.append(head, advice);
    ul.append(li);
  }
  page.append(ul);
}

// fillDecisions — вкладка «Решения»: принять, игнорировать,
// отложить (NR-033 п.4).
function fillDecisions(info: DeviceInfo, decisions: MapSignal[], handlers: CardHandlers): void {
  const page = document.getElementById('card-page-decisions');
  if (page === null) return;
  page.textContent = '';
  const h = el('h3');
  text(h, 'Требуют решения');
  page.append(h);
  if (decisions.length === 0) {
    emptyNote(page, 'Открытых решений нет: сигналов, требующих вашего выбора, устройство не имеет.');
    return;
  }
  for (const s of decisions) {
    const box = el('div', 'decision-box');
    const p = el('p');
    text(p, s.text);
    box.append(p);
    const row = el('div', 'row');
    const accept = (klass: string, label: string): void => {
      const b = el('button') as HTMLButtonElement;
      b.type = 'button';
      text(b, label);
      b.addEventListener('click', () => handlers.onAccept(info.id, klass));
      row.append(b);
    };
    accept('managed', 'Принять: моё (управляемое)');
    accept('known_no_agent', 'Принять: известное');
    accept('guest', 'Принять: гость');
    box.append(row);
    const row2 = el('div', 'row');
    const days = el('select') as HTMLSelectElement;
    days.id = `snooze-days-${s.kind}`;
    for (const d of [1, 7, 30]) {
      const opt = document.createElement('option');
      opt.value = String(d);
      text(opt, `${d} дн.`);
      days.append(opt);
    }
    row2.append(days);
    const ignore = el('button') as HTMLButtonElement;
    ignore.type = 'button';
    text(ignore, 'Игнорировать на выбранный срок');
    ignore.addEventListener('click', () => {
      const selected = Number(days.value || '7');
      handlers.onSnooze(info.id, s.kind, Number.isFinite(selected) ? selected : 7);
    });
    row2.append(ignore);
    const later = el('button') as HTMLButtonElement;
    later.type = 'button';
    text(later, 'Отложить');
    later.title = 'Сигнал остаётся в панели «Требуют внимания», решение можно принять позже';
    later.addEventListener('click', handlers.onClose);
    row2.append(later);
    box.append(row2);
    page.append(box);
  }
}

// fillLinks — вкладка «Связи»: связи узла с портами и источниками.
function fillLinks(info: DeviceInfo, graph: Graph, handlers: CardHandlers): void {
  const page = document.getElementById('card-page-links');
  if (page === null) return;
  page.textContent = '';
  const links = graph.links.filter((l) => l.a === info.id || l.b === info.id);
  if (links.length === 0) {
    emptyNote(page, 'Связей нет: устройство ни к чему не подключено.');
    return;
  }
  const ul = el('ul');
  for (const l of links) {
    const li = el('li');
    const other = l.a === info.id ? l.b : l.a;
    const port = l.a === info.id ? l.aPort : l.bPort;
    const source = linkSource(l.source, l.manual);
    text(li, `${other}${port !== '' ? ` (${port})` : ''} — ${source}`);
    if (l.manual) {
      const b = el('button') as HTMLButtonElement;
      b.type = 'button';
      text(b, 'Разорвать');
      b.addEventListener('click', () => handlers.onDisconnect(info.id));
      li.append(document.createTextNode(' '), b);
    }
    ul.append(li);
  }
  page.append(ul);
}

function linkSource(source: string, manual: boolean): string {
  if (manual) return 'вручную';
  switch (source) {
    case 'lldp': return 'LLDP';
    case 'fdb': return 'таблица MAC';
    case 'inferred': return 'вывод построителя';
    case 'assumed': return 'предполагаемая связь';
    default: return source;
  }
}

// fillHistory — вкладка «История»: записи журнала аудита.
function fillHistory(info: DeviceInfo): void {
  const page = document.getElementById('card-page-history');
  if (page === null) return;
  page.textContent = '';
  if (info.history === undefined || info.history.length === 0) {
    emptyNote(page, 'Изменений не зафиксировано.');
    return;
  }
  const ul = el('ul');
  for (const h of info.history) {
    const li = el('li');
    text(li, `${fmtTime(h.at)} — ${h.actor}: ${h.action}${h.detail ? ` — ${h.detail}` : ''}`);
    ul.append(li);
  }
  page.append(ul);
}
