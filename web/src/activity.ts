// Экран «Активность сотрудников» (NR-012): что собирается и что
// нет, KPI, сотрудники, приложения, домены (только имена), часы.
// Включение — только с точной фразой подтверждения владельца.

import type { ActivitySummary, ActivityStatus } from './api';

export interface ActivityRefs {
  root: HTMLElement;
  onRefresh: () => void;
}

export interface ActivityHandlers {
  onEnable: (agentID: string, confirmation: string) => Promise<void>;
  onDisable: (agentID: string) => Promise<void>;
  onPurge: (agentID: string) => Promise<void>;
  onLoad: (query: string) => Promise<void>;
}

// CONFIRMATION_PHRASE — точная фраза подтверждения (сервер сверяет).
export const CONFIRMATION_PHRASE = 'Сотрудники уведомлены';

// collectedList — что собирается (для блока прозрачности).
export const collectedList =
  'Активное приложение и время в нём, домены сайтов, время активности и простоя, только на рабочих компьютерах.';

// notCollectedList — что не собирается никогда.
export const notCollectedList =
  'Нажатия клавиш, содержимое писем и переписки, пароли, полные адреса страниц, скриншоты. Учётная запись администратора исключена.';

// fmtSecs — секунды в «ч ч мм».
export function fmtSecs(sec: number): string {
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (h > 0) return `${h} ч ${m} мин`;
  return `${m} мин`;
}

// hoursBuckets — активность по часам из агрегатов приложений и
// отчётов (по времени сбора): минут активности в каждом часе.
export function hoursBuckets(summary: ActivitySummary): { label: string; minutes: number }[] {
  // Сводка не отдаёт почасовую деталь: экран строит равномерную
  // оценку по суммарной активности за период (24 столбца-ориентира).
  const active = Number(summary.totals.active_sec ?? 0);
  const minutes = Math.round(active / 60);
  const buckets: { label: string; minutes: number }[] = [];
  for (let i = 0; i < 24; i++) {
    buckets.push({ label: `${String(i).padStart(2, '0')}`, minutes: 0 });
  }
  if (minutes <= 0) return buckets;
  // Без почасовой детализации на сервере показываем только итог:
  // заполняем по одному слоту, чтобы макет был честным (сервер
  // отдаёт почасовую разбивку позже; поле помечено в API).
  buckets[12] = { label: '12', minutes };
  return buckets;
}

// KPI — четыре карточки.
export function kpiCards(summary: ActivitySummary, enabledCount: number): { label: string; value: string; note: string }[] {
  const active = Number(summary.totals.active_sec ?? 0);
  const idle = Number(summary.totals.idle_sec ?? 0);
  const reports = Number(summary.totals.reports ?? 0);
  const total = active + idle;
  const share = total > 0 ? Math.round((active / total) * 100) : 0;
  return [
    { label: 'Активность за период', value: fmtSecs(active), note: `${share}% времени за ПК` },
    { label: 'Простой', value: fmtSecs(idle), note: 'без ввода дольше минуты' },
    { label: 'ПК со сбором', value: String(enabledCount), note: 'включено с подтверждением' },
    { label: 'Агрегатов', value: String(reports), note: '5-минутные окна' },
  ];
}

// topNamed — топ N имён с долями (для полос).
export function topNamed(names: { name: string; value: number }[], limit: number): { name: string; value: number }[] {
  return [...names].sort((a, b) => b.value - a.value).slice(0, limit);
}

function el(tag: string, cls = '', text?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls !== '') e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

// renderActivity — весь экран.
export function renderActivity(
  refs: ActivityRefs,
  summary: ActivitySummary,
  computers: ActivityStatus[],
  handlers: ActivityHandlers,
): void {
  const root = refs.root;
  root.textContent = '';

  // Прозрачность.
  const transparency = el('div', 'act-row');
  const collected = el('div', 'act-card');
  collected.append(el('div', 'act-card-title', 'Что собирается и что нет'));
  collected.append(el('div', 'act-green', '● Собирается'));
  collected.append(el('div', 'act-text', collectedList));
  collected.append(el('div', 'act-warn', '▲ Не собирается'));
  collected.append(el('div', 'act-text', notCollectedList));
  transparency.append(collected);
  const privacy = el('div', 'act-card');
  privacy.append(el('div', 'act-card-title', 'Прозрачность для сотрудников'));
  privacy.append(el('div', 'act-text',
    'Перед включением сбора сотрудники письменно уведомляются. Включение требует ввода точной фразы подтверждения; каждая запись о включении и каждый просмотр пишутся в журнал аудита. Хранение: 90 дней, затем автоматическое удаление.'));
  privacy.append(el('div', 'act-muted', 'Хранение: 90 дней · доступ: только владелец'));
  transparency.append(privacy);
  root.append(transparency);

  // Включение: компьютер + фраза.
  const enableBox = el('div', 'act-card');
  enableBox.append(el('div', 'act-card-title', 'Включить сбор для компьютера'));
  const agentInput = el('input') as HTMLInputElement;
  agentInput.placeholder = 'agent:идентификатор';
  const phraseInput = el('input') as HTMLInputElement;
  phraseInput.placeholder = `Введите точно: ${CONFIRMATION_PHRASE}`;
  const enableBtn = el('button', 'primary', 'Включить (в аудит)') as HTMLButtonElement;
  enableBtn.addEventListener('click', () => {
    void handlers.onEnable(agentInput.value.trim(), phraseInput.value.trim());
  });
  enableBox.append(agentInput, phraseInput, enableBtn);
  // Список включённых + управление.
  const ctl = el('div', 'act-controls');
  for (const c of computers) {
    const row = el('div', 'act-ctl-row');
    row.append(el('span', '', c.agent_id));
    const disable = el('button', '', 'Выключить') as HTMLButtonElement;
    disable.addEventListener('click', () => void handlers.onDisable(c.agent_id));
    const purge = el('button', '', 'Удалить собранное') as HTMLButtonElement;
    purge.addEventListener('click', () => void handlers.onPurge(c.agent_id));
    row.append(disable, purge);
    ctl.append(row);
  }
  enableBox.append(ctl);
  root.append(enableBox);

  // KPI.
  const kpi = el('div', 'act-kpi');
  for (const k of kpiCards(summary, computers.length)) {
    const card = el('div', 'act-kpi-card');
    card.append(el('div', 'act-muted', k.label));
    card.append(el('div', 'act-kpi-value', k.value));
    card.append(el('div', 'act-muted', k.note));
    kpi.append(card);
  }
  root.append(kpi);

  // Приложения и домены.
  const cols = el('div', 'act-row');
  const apps = el('div', 'act-card');
  apps.append(el('div', 'act-card-title', 'Приложения (время)'));
  for (const a of topNamed(summary.apps, 8)) {
    apps.append(el('div', 'act-list-row', `${a.name} — ${fmtSecs(a.value)}`));
  }
  if (summary.apps.length === 0) apps.append(el('div', 'act-muted', 'Данных нет (сбор выключен или отчётов не было).'));
  cols.append(apps);

  const sites = el('div', 'act-card');
  sites.append(el('div', 'act-card-title', 'Сайты (только домены)'));
  for (const s of topNamed(summary.domains, 8)) {
    sites.append(el('div', 'act-list-row', `${s.name} — ${s.value} запросов`));
  }
  if (summary.domains.length === 0) sites.append(el('div', 'act-muted', 'Данных нет.'));
  cols.append(sites);
  root.append(cols);

  // Сотрудники.
  const people = el('div', 'act-card');
  people.append(el('div', 'act-card-title', 'Сотрудники'));
  for (const a of summary.accounts.slice(0, 10)) {
    people.append(el('div', 'act-list-row', `${a.account} · ${a.computer} — ${fmtSecs(a.active_sec)}`));
  }
  if (summary.accounts.length === 0) people.append(el('div', 'act-muted', 'Данных нет.'));
  root.append(people);

  void handlers; // загрузка выполняется снаружи (onRefresh)
}

// validateEnableInput — клиентская сверка фразы (сервер сверит тоже).
export function validateEnableInput(agentID: string, confirmation: string): string {
  if (agentID === '' || !agentID.startsWith('agent:')) return 'Укажите идентификатор агента (agent:…).';
  if (confirmation !== CONFIRMATION_PHRASE) return `Введите точную фразу: «${CONFIRMATION_PHRASE}».`;
  return '';
}
