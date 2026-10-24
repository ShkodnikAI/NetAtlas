// Экран «Скрипты и тесты» (NR-011): репозиторий скриптов, статусы
// конвейера, кнопки только для допустимых переходов, подпись
// владельца с подтверждением вводом имени и хэша, задания и журнал.
// Всё — данные сервера; шлюз на сервере не пропустит то, что
// интерфейс показал ошибочно.

import type { CheckRow, JobRow, SignatureRow, ScriptRow, VersionRow } from './api';

export interface ScriptsRefs {
  root: HTMLElement;
  onRefresh: () => void;
}

export interface ScriptsData {
  scripts: ScriptRow[];
  versions: VersionRow[];
  stages: Record<string, number>;
  jobs: JobRow[];
  catalog: CatalogTemplate[];
  audit: AuditEntry[];
}

export interface CatalogTemplate {
  key: string;
  title: string;
  description: string;
  read_only: boolean;
  params: CatalogParam[];
}

export interface CatalogParam {
  key: string;
  title: string;
  type: string;
  default: string;
  required?: boolean;
  pattern?: string;
  min?: number;
  max?: number;
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor: string;
  action: string;
  target: string;
  result: string;
  detail?: string;
}

export interface ScriptHandlers {
  onSelect: (scriptId: number) => void;
  onCreateDraft: (body: Record<string, unknown>) => Promise<void>;
  onStatus: (sid: number, vid: number, to: string, comment: string) => Promise<void>;
  onSign: (sid: number, vid: number, name: string, sha: string) => void;
  onCheckRun: (sid: number, vid: number) => Promise<void>;
  onCheckResult: (sid: number, vid: number, body: Record<string, unknown>) => Promise<void>;
  onViewCode: (sid: number, vid: number) => Promise<void>;
  onCreateJob: (body: Record<string, unknown>) => Promise<void>;
  onStopJob: (jobId: number) => Promise<void>;
}

// Имена и цвета статусов конвейера (цвета макета Scripts.dc.html).
export const stageNames: Record<string, string> = {
  draft: 'Черновик',
  checked: 'Проверка кода',
  tested: 'Тест на ВМ',
  signed: 'Подпись',
  pilot: 'Один ПК',
  released: 'Раскатка',
  rejected: 'Отклонён',
};

export const stageColors: Record<string, string> = {
  draft: '#7C8798',
  checked: '#7C8798',
  tested: '#F5B83D',
  signed: '#5AA9FF',
  pilot: '#5AA9FF',
  released: '#5FD38D',
  rejected: '#E06060',
};

// chain — порядок конвейера для вычисления следующего шага.
export const chain = ['draft', 'checked', 'tested', 'signed', 'pilot', 'released'];

// nextStatus — следующий по цепочке; у released нет.
export function nextStatus(status: string): string | null {
  const i = chain.indexOf(status);
  if (i < 0 || i + 1 >= chain.length) return null;
  return chain[i + 1] ?? null;
}

// allowedActions — кнопки, которые интерфейс показывает для статуса:
// только переход вперёд на один шаг (подпись — для tested) и rejected.
export function allowedActions(status: string): { kind: 'status' | 'sign' | 'rejected'; to: string; label: string }[] {
  const out: { kind: 'status' | 'sign' | 'rejected'; to: string; label: string }[] = [];
  if (status === 'rejected') return out;
  const next = nextStatus(status);
  if (next !== null) {
    if (next === 'signed') {
      out.push({ kind: 'sign', to: 'signed', label: 'Подписать' });
    } else {
      out.push({ kind: 'status', to: next, label: `Перевести: ${stageNames[next]}` });
    }
  }
  out.push({ kind: 'rejected', to: 'rejected', label: 'Вернуть на доработку' });
  return out;
}

// validateSignInput — подтверждение подписи: имя скрипта и хэш
// должны совпасть точно. Возвращает текст ошибки или пустую строку.
export function validateSignInput(name: string, expectedName: string, sha: string, expectedSha: string): string {
  if (name !== expectedName) return 'Имя скрипта не совпадает: подписывается то, что вы видите.';
  const normalized = sha.trim().toLowerCase().replace(/[\s:-]/g, '');
  if (normalized !== expectedSha.toLowerCase()) return 'Хэш не совпадает с версией: скопируйте его из карточки.';
  return '';
}

// signActions — действия конвейера, попадающие в журнал экрана.
const scriptActions = new Set([
  'script_create', 'script_version_create', 'script_status', 'script_check',
  'script_sign', 'job_create', 'job_stop', 'job_dispatch', 'job_result', 'job_autostop', 'job_expired',
]);

// filterScriptAudit — записи журнала, относящиеся к конвейеру.
export function filterScriptAudit(entries: AuditEntry[]): AuditEntry[] {
  return entries.filter((e) => scriptActions.has(e.action));
}

function el(tag: string, cls = '', text?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls !== '') e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

// renderStages — карточки этапов конвейера со счётчиками.
export function renderStages(root: HTMLElement, stages: Record<string, number>): void {
  root.textContent = '';
  for (const status of chain) {
    const card = el('div', 'scr-stage');
    card.style.borderTopColor = stageColors[status] ?? '';
    card.append(el('div', 'scr-stage-name', stageNames[status]));
    card.append(el('div', 'scr-stage-count', String(stages[status] ?? 0)));
    root.append(card);
  }
}

// renderScriptList — список скриптов с последними статусами.
export function renderScriptList(
  root: HTMLElement,
  scripts: ScriptRow[],
  versions: Record<number, VersionRow | undefined>,
  selectedId: number | null,
  onSelect: (id: number) => void,
): void {
  root.textContent = '';
  if (scripts.length === 0) {
    root.append(el('p', 'muted', 'Скриптов ещё нет: создайте черновик из каталога или из текста.'));
    return;
  }
  for (const s of scripts) {
    const row = el('div', 'scr-item');
    if (s.id === selectedId) row.classList.add('selected');
    const v = versions[s.id];
    const head = el('div', 'scr-item-head');
    head.append(el('div', 'scr-item-name', s.name));
    head.append(el('div', 'scr-item-ver', v ? `v${v.version}` : ''));
    row.append(head);
    const status = el('div', 'scr-item-status', v ? `${stageNames[v.status] ?? v.status}` : '');
    if (v) status.style.color = stageColors[v.status] ?? '';
    row.append(status);
    row.addEventListener('click', () => onSelect(s.id));
    root.append(row);
  }
}

// renderVersionCard — карточка выбранной версии: шаги конвейера,
// кнопки допустимых переходов, проверки, подпись, задания.
export function renderVersionCard(
  root: HTMLElement,
  script: ScriptRow,
  version: VersionRow,
  checks: CheckRow[],
  signature: SignatureRow | undefined,
  jobs: JobRow[],
  handlers: ScriptHandlers,
): void {
  root.textContent = '';

  const head = el('div', 'scr-card-head');
  const title = el('div', 'scr-card-title', script.name);
  head.append(title);
  head.append(el('div', 'scr-item-ver', `v${version.version} · ${script.kind === 'catalog' ? 'каталог' : 'скрипт'} · ${script.category}`));
  root.append(head);

  const statusRow = el('div', 'scr-status-row');
  const badge = el('span', 'scr-badge', stageNames[version.status] ?? version.status);
  badge.style.borderColor = stageColors[version.status] ?? '';
  badge.style.color = stageColors[version.status] ?? '';
  statusRow.append(badge);
  if (version.pilot_ok) statusRow.append(el('span', 'scr-badge', 'пилот пройден'));
  if (signature) {
    statusRow.append(el('span', 'scr-badge', `подпись до ${signature.expires_at.slice(0, 10)}`));
  }
  root.append(statusRow);

  // Кнопки только для допустимых переходов.
  const btnRow = el('div', 'scr-buttons');
  for (const a of allowedActions(version.status)) {
    const b = el('button', '', a.label) as HTMLButtonElement;
    if (a.kind === 'sign') b.classList.add('primary');
    b.addEventListener('click', () => {
      if (a.kind === 'sign') {
        handlers.onSign(script.id, version.id, script.name, version.sha256);
      } else if (a.kind === 'rejected') {
        const comment = window.prompt('Причина возврата на доработку (записывается в аудит):');
        if (comment === null || comment.trim() === '') return;
        void handlers.onStatus(script.id, version.id, 'rejected', comment.trim());
      } else {
        const comment = window.prompt(`Комментарий к переходу «${stageNames[a.to]}» (ручная отметка требует причины):`);
        if (comment === null || comment.trim() === '') return;
        void handlers.onStatus(script.id, version.id, a.to, comment.trim());
      }
    });
    btnRow.append(b);
  }
  // Проверки: серверный запуск (если pwsh есть) и запись результата стенда.
  const runBtn = el('button', '', 'Запустить статические проверки') as HTMLButtonElement;
  runBtn.addEventListener('click', () => void handlers.onCheckRun(script.id, version.id));
  btnRow.append(runBtn);
  const standBtn = el('button', '', 'Записать результат теста на ВМ') as HTMLButtonElement;
  standBtn.addEventListener('click', () => {
    const detail = window.prompt('Результат со стенда (что наблюдали):');
    if (detail === null || detail.trim() === '') return;
    void handlers.onCheckResult(script.id, version.id, { kind: 'vm', source: 'stand', result: 'pass', detail: detail.trim() });
  });
  btnRow.append(standBtn);
  const codeBtn = el('button', '', 'Посмотреть код') as HTMLButtonElement;
  codeBtn.addEventListener('click', () => {
    void handlers.onViewCode(script.id, version.id);
  });
  btnRow.append(codeBtn);
  root.append(btnRow);

  // Хэш версии — для подтверждения подписи.
  const shaRow = el('div', 'scr-sha');
  shaRow.append(el('span', 'muted', 'SHA-256 содержимого: '));
  shaRow.append(el('code', 'scr-sha-value', version.sha256));
  root.append(shaRow);

  // Проверки и тесты.
  if (checks.length > 0) {
    const box = el('div', 'scr-section');
    box.append(el('div', 'scr-section-title', 'Проверки и тесты'));
    for (const c of checks.slice(0, 8)) {
      const row = el('div', 'scr-check');
      const verdict = c.result === 'pass' ? 'пройдено' : 'провалено';
      row.append(el('span', `scr-check-result ${c.result === 'pass' ? 'ok' : 'bad'}`, verdict));
      row.append(el('span', 'muted', `${c.kind === 'vm' ? 'тест на ВМ' : 'статическая'} · ${c.source} · ${c.actor}`));
      if (c.comment !== '') row.append(el('span', '', ` — ${c.comment}`));
      box.append(row);
    }
    root.append(box);
  }

  // Задания версии.
  const jobsBox = el('div', 'scr-section');
  jobsBox.append(el('div', 'scr-section-title', 'Задания'));
  if (jobs.length === 0) {
    jobsBox.append(el('p', 'muted', 'Заданий нет. Создание задания не отправляет его агентам: выдача идёт через шлюз в checkin.'));
  }
  for (const j of jobs) {
    const row = el('div', 'scr-job');
    const left = el('div', 'scr-job-info');
    left.append(el('div', '', `#${j.id} · ${j.name} · ${j.status}${j.pilot ? ' · пилот' : ''}`));
    const states = j.targets.map((t) => `${t.agent_id.replace('agent:', '')}: ${t.state}`).join(', ');
    left.append(el('div', 'muted', states));
    row.append(left);
    if (j.status === 'pending' || j.status === 'running') {
      const stop = el('button', '', 'Остановить') as HTMLButtonElement;
      stop.addEventListener('click', () => void handlers.onStopJob(j.id));
      row.append(stop);
    }
    jobsBox.append(row);
  }
  const newJob = el('button', '', 'Создать задание') as HTMLButtonElement;
  if (version.status === 'draft' || version.status === 'checked' || version.status === 'rejected') {
    newJob.disabled = true;
    newJob.title = 'Задание создаётся на подписанную версию';
  }
  newJob.addEventListener('click', () => {
    const targetsRaw = window.prompt('Агенты через запятую (идентификаторы agent:…):');
    if (targetsRaw === null) return;
    const targets = targetsRaw.split(',').map((s) => s.trim()).filter((s) => s !== '');
    if (targets.length === 0) return;
    void handlers.onCreateJob({
      script_version_id: version.id,
      targets,
      pilot: window.confirm('Пилотное задание на один ПК?'),
    });
  });
  jobsBox.append(newJob);
  root.append(jobsBox);
}

// renderCatalogPicker — форма создания черновика: из каталога или
// из текста. Всегда draft.
export function renderDraftForm(
  root: HTMLElement,
  templates: CatalogTemplate[],
  handlers: ScriptHandlers,
): void {
  root.textContent = '';
  const title = el('div', 'scr-section-title', 'Новый черновик');
  root.append(title);

  const row = el('div', 'scr-draft-row');
  const mode = el('select') as HTMLSelectElement;
  mode.append(new Option('Из каталога действий', 'catalog'));
  mode.append(new Option('Из текста (например, из рекомендации)', 'script'));
  row.append(mode);

  const tpl = el('select') as HTMLSelectElement;
  for (const t of templates) tpl.append(new Option(`${t.title}${t.read_only ? ' (только чтение)' : ''}`, t.key));
  row.append(tpl);

  const name = el('input') as HTMLInputElement;
  name.placeholder = 'Название скрипта';
  name.maxLength = 200;
  row.append(name);

  const params = el('div', 'scr-draft-params');
  const fillParams = (): void => {
    params.textContent = '';
    const t = templates.find((x) => x.key === tpl.value);
    if (!t) return;
    for (const p of t.params) {
      const input = el('input') as HTMLInputElement;
      input.dataset.param = p.key;
      input.placeholder = `${p.title} (${p.type}${p.min !== undefined ? `, ${p.min}..${p.max ?? ''}` : ''})`;
      input.value = p.default ?? '';
      params.append(input);
    }
  };
  fillParams();
  tpl.addEventListener('change', fillParams);
  root.append(row);
  root.append(params);

  const text = el('textarea') as HTMLTextAreaElement;
  text.placeholder = 'Текст PowerShell-скрипта (для режима «из текста»)';
  text.hidden = true;
  root.append(text);
  mode.addEventListener('change', () => {
    const isCatalog = mode.value === 'catalog';
    tpl.hidden = !isCatalog;
    params.hidden = !isCatalog;
    text.hidden = isCatalog;
  });

  const create = el('button', 'primary', 'Создать черновик') as HTMLButtonElement;
  create.addEventListener('click', () => {
    const body: Record<string, unknown> = {
      name: name.value.trim(),
      kind: mode.value,
      category: 'general',
    };
    if (mode.value === 'catalog') {
      body.catalog_key = tpl.value;
      const map: Record<string, string> = {};
      for (const input of Array.from(params.querySelectorAll('input'))) {
        const key = (input as HTMLInputElement).dataset.param;
        if (key) map[key] = (input as HTMLInputElement).value;
      }
      body.params = map;
    } else {
      body.content = text.value;
    }
    void handlers.onCreateDraft(body);
  });
  root.append(create);
}

// renderScriptAudit — журнал действий конвейера.
export function renderScriptAudit(root: HTMLElement, entries: AuditEntry[]): void {
  root.textContent = '';
  const list = filterScriptAudit(entries).slice(0, 12);
  if (list.length === 0) {
    root.append(el('p', 'muted', 'Действий конвейера пока нет.'));
    return;
  }
  for (const e of list) {
    const row = el('div', 'scr-audit-row');
    row.append(el('span', 'scr-audit-time', e.ts.replace('T', ' ').slice(0, 19)));
    row.append(el('span', 'scr-audit-actor', e.actor));
    row.append(el('span', 'scr-audit-action', `${e.action} → ${e.target}`));
    row.append(el('span', `scr-check-result ${e.result === 'ok' ? 'ok' : 'bad'}`, e.result));
    root.append(row);
  }
}
