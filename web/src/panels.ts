// Правая панель устройства: вкладки «Обзор», «Диски», «Пользователь»,
// «Сеть», «Правка». Все данные из API недоверенные: подписи
// вставляются как текст (textContent), не как HTML.

import type { DeviceInfo, Graph, LinkInfo } from './api';
import { svgIcon } from './nodes';

export interface PanelHandlers {
  onRename: (id: string, name: string) => void;
  onClass: (id: string, klass: string) => void;
  // onKind — ручной выбор типа узла (NR-032 п.1): перекрывает
  // автоматический вывод классификатора.
  onKind: (id: string, kind: string) => void;
  onVerify: (id: string) => void;
  onDelete: (id: string) => void;
}

export const CLASSES: [string, string][] = [
  ['managed', 'управляемое (с агентом)'],
  ['known_no_agent', 'известное без агента'],
  ['guest', 'гость'],
  ['unknown', 'неизвестное'],
];

export const KIND_LABELS: Record<string, string> = {
  internet: 'интернет',
  router: 'роутер',
  switch: 'коммутатор',
  ap: 'точка доступа',
  server: 'сервер',
  device: 'компьютер',
  laptop: 'ноутбук',
  printer: 'принтер',
  phone: 'телефон',
  iot: 'IoT-устройство',
  tv: 'телевизор',
  cloud: 'неуправляемый коммутатор',
  unknown: 'неизвестное устройство',
};

// KIND_OPTIONS — типы узла, доступные владельцу для ручного выбора.
export const KIND_OPTIONS: [string, string][] = [
  ['device', 'компьютер'],
  ['laptop', 'ноутбук'],
  ['server', 'сервер'],
  ['router', 'роутер'],
  ['switch', 'коммутатор'],
  ['ap', 'точка доступа'],
  ['printer', 'принтер'],
  ['phone', 'телефон'],
  ['iot', 'IoT-устройство'],
  ['tv', 'телевизор'],
  ['internet', 'интернет'],
  ['cloud', 'неуправляемый коммутатор'],
  ['unknown', 'неизвестное'],
];

function el(tag: string, className?: string): HTMLElement {
  const e = document.createElement(tag);
  if (className) e.className = className;
  return e;
}

// text — безопасная вставка строки: только textContent.
function text(parent: HTMLElement, value: string): void {
  parent.textContent = value;
}

// kindIcon — маленький значок роли (NR-036 п.1): диск цвета роли с
// белым глифом; источник — статическая таблица типов, не данные API.
export function kindIcon(kind: string, size = 20): HTMLImageElement {
  const img = document.createElement('img');
  img.src = svgIcon(kind);
  img.alt = '';
  img.width = size;
  img.height = size;
  img.className = 'kv-icon';
  return img;
}

// fillOverview — вкладка «Обзор»: тип, имя, IP, MAC, производитель,
// класс, SSID; метки «вручную» и «не проверен». Тип, выведенный
// классификатором, помечается «определён автоматически, изменить»
// (NR-032 п.1); ручной — «указан вручную».
export function fillOverview(
  page: HTMLElement,
  info: DeviceInfo,
  kind: string,
  onChangeKind: () => void = () => undefined,
  onOpenCard: () => void = () => undefined,
): void {
  page.textContent = '';
  const dl = el('dl', 'kv');
  const row = (dt: string, dd: string): void => {
    const t = el('dt');
    text(t, dt);
    const d = el('dd');
    text(d, dd);
    dl.append(t, d);
  };
  // Тип: автоматический вывод помечается и даёт «изменить»; ручной
  // выбор владельца сильнее классификатора. NR-036 п.1: перед
  // подписью типа — значок роли.
  const typeRow = el('div', 'kv-row');
  const dt = el('dt');
  text(dt, 'Тип');
  const dd = el('dd');
  dd.append(kindIcon(kind), document.createTextNode(KIND_LABELS[kind] ?? 'неизвестное устройство'));
  if (info.kindManual) {
    const b = el('span', 'badge manual');
    text(b, 'указан вручную');
    dd.append(document.createTextNode(' '), b);
  } else if (info.kindAuto !== '' && info.kindAuto === kind) {
    dd.append(document.createTextNode(' (определён автоматически, '));
    const change = el('button', 'link') as HTMLButtonElement;
    change.type = 'button';
    text(change, 'изменить');
    change.addEventListener('click', onChangeKind);
    dd.append(change, document.createTextNode(')'));
  }
  typeRow.append(dt, dd);
  dl.append(typeRow);
  row('ID', info.id);
  if (info.hostname !== '') row('Имя', info.hostname);
  row('IP', info.ips.length > 0 ? info.ips.join(', ') : '—');
  if (info.vendor !== '') row('Производитель', info.vendor);
  row('Класс', className(info.class));
  if (info.ssid !== '') row('SSID', info.ssid);
  page.append(dl);

  const marks = el('p');
  if (info.manual) {
    const b = el('span', 'badge manual');
    text(b, 'вручную');
    marks.append(b, document.createTextNode(' '));
  }
  if (!info.verified) {
    const b = el('span', 'badge unverified');
    text(b, 'не проверен');
    marks.append(b);
  }
  if (marks.childNodes.length > 0) page.append(marks);

  // NR-033 п.3: одинарный клик — краткая панель, полная карточка —
  // по двойному клику или по этой кнопке.
  const open = el('button', 'link') as HTMLButtonElement;
  open.type = 'button';
  text(open, 'Открыть полную карточку');
  open.addEventListener('click', onOpenCard);
  page.append(open);
}

// className — человекочитаемое название класса.
export function className(klass: string): string {
  for (const [value, label] of CLASSES) {
    if (value === klass) return label;
  }
  return klass;
}

// fillNet — вкладка «Сеть»: связи узла с портами и наблюдения.
export function fillNet(page: HTMLElement, id: string, graph: Graph): void {
  page.textContent = '';
  const links = graph.links.filter((l) => l.a === id || l.b === id);
  if (links.length > 0) {
    const h = el('h3');
    text(h, 'Связи');
    const ul = el('ul');
    for (const l of links) {
      const li = el('li');
      const other = l.a === id ? l.b : l.a;
      const port = l.a === id ? l.aPort : l.bPort;
      text(li, `${other}${port !== '' ? ` (${port})` : ''} — ${linkSource(l)}`);
      ul.append(li);
    }
    page.append(h, ul);
  }
  const h2 = el('h3');
  text(h2, 'Наблюдения');
  const ul2 = el('ul');
  for (const o of graphObservations(page, id)) {
    const li = el('li');
    text(li, `${o.source} — ${o.seen}`);
    ul2.append(li);
  }
  if (ul2.childNodes.length === 0) {
    const li = el('li');
    text(li, 'пока нет наблюдений');
    ul2.append(li);
  }
  page.append(h2, ul2);
}

function graphObservations(_page: HTMLElement, _id: string): { source: string; seen: string }[] {
  // Наблюдения приходят в карточке (DeviceInfo); для графа используется
  // последний ответ API, переданный в setObservations.
  return lastObservations;
}

let lastObservations: { source: string; seen: string }[] = [];

export function setObservations(list: { source: string; seen: string }[]): void {
  lastObservations = list;
}

function linkSource(l: LinkInfo): string {
  switch (l.source) {
    case 'lldp': return 'LLDP';
    case 'fdb': return 'таблица MAC';
    case 'inferred': return 'вывод построителя';
    case 'manual': return 'вручную';
    default: return l.source;
  }
}

// fillEdit — вкладка «Правка»: переименование, класс, проверка,
// удаление (только ручных).
export function fillEdit(
  page: HTMLElement,
  info: DeviceInfo,
  handlers: PanelHandlers,
): void {
  page.textContent = '';

  const nameId = 'edit-name';
  const nameLabel = el('label');
  nameLabel.setAttribute('for', nameId);
  text(nameLabel, 'Название');
  const name = el('input') as HTMLInputElement;
  name.type = 'text';
  name.id = nameId;
  name.maxLength = 255;
  name.value = info.hostname;
  const save = el('button');
  text(save, 'Сохранить название');
  save.addEventListener('click', () => handlers.onRename(info.id, name.value));

  const classLabel = el('label');
  classLabel.setAttribute('for', 'edit-class');
  text(classLabel, 'Класс');
  const select = el('select') as HTMLSelectElement;
  select.id = 'edit-class';
  for (const [value, label] of CLASSES) {
    const opt = document.createElement('option');
    opt.value = value;
    text(opt, label);
    if (value === info.class) opt.selected = true;
    select.append(opt);
  }
  const apply = el('button');
  text(apply, 'Сменить класс');
  apply.addEventListener('click', () => handlers.onClass(info.id, select.value));

  // Тип узла (NR-032 п.1): ручной выбор перекрывает автоматический.
  const kindLabel = el('label');
  kindLabel.setAttribute('for', 'edit-kind');
  text(kindLabel, 'Тип устройства');
  const kindSelect = el('select') as HTMLSelectElement;
  kindSelect.id = 'edit-kind';
  for (const [value, label] of KIND_OPTIONS) {
    const opt = document.createElement('option');
    opt.value = value;
    text(opt, label);
    if (value === info.kind) opt.selected = true;
    kindSelect.append(opt);
  }
  const kindApply = el('button');
  text(kindApply, 'Сменить тип');
  kindApply.addEventListener('click', () => handlers.onKind(info.id, kindSelect.value));

  const verdict = el('div', 'verdict');

  const check = el('button');
  text(check, 'Проверить (ping)');
  check.addEventListener('click', () => handlers.onVerify(info.id));

  const row1 = el('div', 'row');
  row1.append(save);
  const row2 = el('div', 'row');
  row2.append(apply);
  const row3 = el('div', 'row');
  row3.append(kindApply);
  const row4 = el('div', 'row');
  row4.append(check);

  page.append(nameLabel, name, row1, classLabel, select, row2, kindLabel, kindSelect, row3, verdict, row4);

  if (info.manual) {
    const del = el('button');
    text(del, 'Удалить ручной элемент');
    del.addEventListener('click', () => handlers.onDelete(info.id));
    const row5 = el('div', 'row');
    row5.append(del);
    page.append(row5);
  }
}
