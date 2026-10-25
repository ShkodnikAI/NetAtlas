// Экран «Отчёт для ИИ» (NR-013): граница изоляции. Сервер собирает
// отчёт по единой форме, очищает его и показывает владельцу
// предпросмотр; дальше — вручную (копировать/вставить) или модель,
// если владелец включил её на сервере (--ai-enabled). Ответ ИИ —
// всегда предложение: из него создаётся только черновик скрипта
// (NR-011), исполнение и подпись из ответа невозможны.

import type { AIReportItem, AIReportFull, AIMappingRow } from './api';

export interface ReportsRefs {
  root: HTMLElement;
  onRefresh: () => void;
}

export interface ReportsHandlers {
  onCreate: (topic: string, agentID: string, question: string) => Promise<void>;
  onOpen: (id: number) => Promise<void>;
  onCopy: (text: string) => void;
  onAnswer: (id: number, text: string) => Promise<void>;
  onAskAI: (id: number) => Promise<void>;
  onDraft: (id: number, name: string, fragment: string) => Promise<void>;
  onMapping: (id: number) => Promise<void>;
}

// REPORT_TOPICS — темы из фиксированного набора сервера.
export const REPORT_TOPICS: { key: string; title: string }[] = [
  { key: 'slow_network', title: 'Медленный интернет' },
  { key: 'disk_full', title: 'Заполнение диска' },
  { key: 'security', title: 'Замечания безопасности' },
  { key: 'custom', title: 'Другое (свой вопрос)' },
];

// topicTitle — подпись темы для списка.
export function topicTitle(topic: string): string {
  const t = REPORT_TOPICS.find((x) => x.key === topic);
  return t ? t.title : 'Другое (свой вопрос)';
}

// statusLabel — статус отчёта по-русски.
export function statusLabel(status: string): string {
  switch (status) {
    case 'open': return 'ждёт ответа';
    case 'answered': return 'есть ответ';
    case 'drafted': return 'создан черновик';
    default: return status;
  }
}

// MaxAnswerBytes — предел ответа ИИ (совпадает с сервером).
export const MaxAnswerBytes = 32 * 1024;

// validateAnswerText — ответ вставляется как текст; пустой и
// длиннее лимита сервер не примет.
export function validateAnswerText(text: string): string {
  if (text.trim() === '') return 'Вставьте ответ ИИ как текст.';
  if (text.length > MaxAnswerBytes) return `Ответ длиннее ${Math.floor(MaxAnswerBytes / 1024)} КБ — сократите.`;
  return '';
}

// validateDraftInput — черновик требует название и фрагмент ответа.
export function validateDraftInput(name: string, fragment: string): string {
  if (name.trim() === '') return 'Укажите название черновика.';
  if (fragment.trim() === '') return 'Вставьте фрагмент ответа ИИ.';
  return '';
}

// boundaryCards — три зоны границы (заголовок экрана).
export function boundaryCards(): { title: string; text: string; cls: string }[] {
  return [
    { title: 'Зона сети', text: 'Агенты, сервер, исполнение команд. ИИ сюда не имеет доступа.', cls: 'rep-zone-net' },
    { title: 'Зона отчёта', text: 'Сервер собирает факты и очищает данные. Здесь вы проверяете текст.', cls: 'rep-zone-report' },
    { title: 'Зона ИИ', text: 'На входе текст, на выходе текст. Мост между зонами — только вы.', cls: 'rep-zone-ai' },
  ];
}

// notSentList — что не уходит ИИ никогда.
export function notSentList(): string[] {
  return [
    'имена компьютеров и учётных записей (заменяются псевдонимами)',
    'IP- и MAC-адреса, домены, пути с пользователями',
    'пароли, токены, ключи и строки подключения',
    'таблица соответствий псевдонимов (только вы, в аудит)',
    'доступ к сети, компьютерам, ключам и репозиторию скриптов',
  ];
}

// injectionWarning — предупреждение владельцу, если в тексте отчёта
// есть пометки внедрения (данные не удалены, но помечены и в аудите).
export function injectionWarning(cleanedText: string): string | null {
  if (!cleanedText.includes('[POSSIBLE_INJECTION]')) return null;
  return 'Обнаружены строки, похожие на попытку внедрить инструкции ИИ. Данные не удалены, но помечены тегом [POSSIBLE_INJECTION] и записаны в аудит. Проверьте их перед отправкой.';
}

// mappingTable — строки таблицы соответствий для показа владельцу.
export function mappingTable(rows: AIMappingRow[]): { alias: string; kind: string; value: string }[] {
  return rows.map((r) => ({ alias: r.alias, kind: kindLabel(r.kind), value: r.value }));
}

// kindLabel — тип замены по-русски.
export function kindLabel(kind: string): string {
  switch (kind) {
    case 'ip': return 'адрес';
    case 'mac': return 'MAC';
    case 'host': return 'компьютер';
    case 'user': return 'учётная запись';
    case 'domain': return 'домен';
    case 'path': return 'путь';
    case 'secret': return 'секрет';
    default: return kind;
  }
}

function el(tag: string, cls = '', text?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls !== '') e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

// renderReports — весь экран: граница, форма создания, список
// отчётов, карточка выбранного (текст, копирование, ответ, черновик,
// таблица соответствий).
export function renderReports(
  refs: ReportsRefs,
  list: AIReportItem[],
  current: AIReportFull | null,
  mapping: AIMappingRow[] | null,
  handlers: ReportsHandlers,
): void {
  const root = refs.root;
  root.textContent = '';

  // Граница: зоны и что не уходит.
  const zones = el('div', 'rep-zones');
  const cards = boundaryCards();
  for (let i = 0; i < cards.length; i++) {
    const c = cards[i]!;
    const card = el('div', 'act-card');
    card.append(el('div', 'rep-zone ' + c.cls, c.title));
    card.append(el('div', 'act-text', c.text));
    zones.append(card);
    if (i < cards.length - 1) zones.append(el('div', 'rep-arrow', '→'));
  }
  root.append(zones);

  const cols = el('div', 'act-row');

  // Форма создания.
  const form = el('div', 'act-card');
  form.append(el('div', 'act-card-title', 'Собрать отчёт'));
  const topicSel = el('select', 'rep-select') as HTMLSelectElement;
  for (const t of REPORT_TOPICS) {
    const opt = el('option') as HTMLOptionElement;
    opt.value = t.key;
    opt.textContent = t.title;
    topicSel.append(opt);
  }
  const agentInput = el('input') as HTMLInputElement;
  agentInput.placeholder = 'агент (необязательно): agent:идентификатор';
  const questionInput = el('input') as HTMLInputElement;
  questionInput.placeholder = 'свой вопрос (необязательно)';
  const createBtn = el('button', 'primary', 'Собрать очищенный отчёт') as HTMLButtonElement;
  createBtn.addEventListener('click', () => {
    void handlers.onCreate(topicSel.value, agentInput.value.trim(), questionInput.value.trim());
  });
  form.append(topicSel, agentInput, questionInput, createBtn);
  const notSent = el('div', 'act-warn', '▲ Не уходит в ИИ никогда');
  form.append(notSent);
  for (const line of notSentList()) {
    form.append(el('div', 'act-muted', '· ' + line));
  }
  cols.append(form);

  // Список отчётов.
  const listBox = el('div', 'act-card');
  listBox.append(el('div', 'act-card-title', 'Отчёты'));
  if (list.length === 0) {
    listBox.append(el('div', 'act-muted', 'Пока нет отчётов.'));
  }
  for (const r of list) {
    const row = el('button', 'rep-item') as HTMLButtonElement;
    row.type = 'button';
    row.append(el('span', '', `№${r.id} · ${topicTitle(r.topic)}`));
    row.append(el('span', 'rep-status', statusLabel(r.status)));
    row.addEventListener('click', () => void handlers.onOpen(r.id));
    listBox.append(row);
  }
  cols.append(listBox);
  root.append(cols);

  // Карточка выбранного отчёта.
  if (current !== null) {
    const card = el('div', 'act-card rep-current');
    card.append(el('div', 'act-card-title', `Отчёт №${current.id} — ${topicTitle(current.topic)} (${statusLabel(current.status)})`));

    // Предпросмотр очищенного текста с предупреждениями + копирование.
    const warn = injectionWarning(current.cleaned_text);
    if (warn !== null) {
      card.append(el('div', 'act-warn', '▲ ' + warn));
    }
    const pre = el('pre', 'rep-pre', current.cleaned_text);
    card.append(pre);
    const copyBtn = el('button', 'primary', 'Скопировать текст для ИИ') as HTMLButtonElement;
    copyBtn.addEventListener('click', () => handlers.onCopy(current.cleaned_text));
    card.append(copyBtn);

    // Ответ: ручная вставка или запрос модели.
    card.append(el('div', 'act-card-title', 'Ответ ИИ (текст-предложение)'));
    const answerArea = el('textarea', 'rep-answer') as HTMLTextAreaElement;
    answerArea.rows = 5;
    if (current.answer) answerArea.value = current.answer;
    card.append(answerArea);
    const answerBtns = el('div', 'act-controls');
    const saveBtn = el('button', 'primary', 'Принять ответ как текст') as HTMLButtonElement;
    saveBtn.addEventListener('click', () => {
      void handlers.onAnswer(current.id, answerArea.value);
    });
    const askBtn = el('button', '', 'Спросить у модели (если включена)') as HTMLButtonElement;
    askBtn.type = 'button';
    askBtn.addEventListener('click', () => void handlers.onAskAI(current.id));
    answerBtns.append(saveBtn, askBtn);
    card.append(answerBtns);
    card.append(el('div', 'act-muted', 'Ответ — только предложение. Исполнение возможно лишь после проверки, теста и вашей подписи (конвейер скриптов).'));

    // Черновик из фрагмента ответа.
    card.append(el('div', 'act-card-title', 'Создать черновик скрипта из фрагмента'));
    const draftName = el('input') as HTMLInputElement;
    draftName.placeholder = 'название черновика';
    const draftFrag = el('textarea', 'rep-answer') as HTMLTextAreaElement;
    draftFrag.rows = 3;
    draftFrag.placeholder = 'фрагмент ответа ИИ (текст)';
    const draftBtn = el('button', 'primary', 'Создать черновик (статус draft)') as HTMLButtonElement;
    draftBtn.addEventListener('click', () => {
      void handlers.onDraft(current.id, draftName.value, draftFrag.value);
    });
    card.append(draftName, draftFrag, draftBtn);

    // Таблица соответствий — только владелец, в аудит.
    const mapBtn = el('button', '', 'Показать таблицу соответствий (в аудит)') as HTMLButtonElement;
    mapBtn.type = 'button';
    mapBtn.addEventListener('click', () => void handlers.onMapping(current.id));
    card.append(mapBtn);
    if (mapping !== null) {
      const tbl = el('table', 'rep-mapping') as HTMLTableElement;
      const head = tbl.createTHead()?.insertRow();
      if (head) {
        for (const h of ['Псевдоним', 'Тип', 'Реальное значение']) {
          head.insertCell().textContent = h;
        }
      }
      const body = tbl.createTBody();
      for (const row of mappingTable(mapping)) {
        const tr = body.insertRow();
        tr.insertCell().textContent = row.alias;
        tr.insertCell().textContent = row.kind;
        tr.insertCell().textContent = row.value;
      }
      card.append(tbl);
      card.append(el('div', 'act-muted', 'Таблица не входит в отчёт и не видна ИИ; этот просмотр записан в аудит.'));
    }
    root.append(card);
  }
}
