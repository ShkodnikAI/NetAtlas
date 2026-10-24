// Экран «Безопасность» (NR-010): оценка, счётчики по серьёзности,
// замечания с основаниями, сетевые наблюдения и карточки
// компьютеров. Всё — текстом от сервера; оценка считается на
// сервере по правилам и весам, без участия ИИ.

import type { SecurityCard, SecurityCheck, SecurityGroup, SecuritySummary } from './api';

export interface SecurityRefs {
  root: HTMLElement;
  onComputer: (id: string) => void;
}

function el(tag: string, cls: string, text?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls !== '') e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

const sevNames: Record<string, string> = {
  critical: 'Критичное',
  warning: 'Важное',
  info: 'Прочее',
  ok: 'Норма',
  unknown: 'Не определено',
};

// scoreText — подпись оценки: без данных «нет данных», а не «всё
// безопасно».
export function scoreText(score: number | null): string {
  if (score === null) return 'нет данных';
  return String(score);
}

// checkStatusName — человеческое имя статуса проверки.
export function checkStatusName(status: string): string {
  switch (status) {
    case 'pass': return 'норма';
    case 'fail': return 'замечание';
    case 'unknown': return 'не определено';
    default: return status;
  }
}

// renderScore — карточка общей оценки.
export function renderScore(root: HTMLElement, score: number | null): void {
  root.textContent = '';
  const big = el('div', 'sec-score-value', scoreText(score));
  if (score === null) big.classList.add('muted');
  else if (score < 50) big.classList.add('severity-critical');
  else if (score < 80) big.classList.add('severity-warning');
  root.append(big);
  const bar = el('div', 'sec-score-bar');
  const fill = el('div', 'sec-score-fill');
  if (score !== null) {
    fill.style.width = `${score}%`;
    if (score < 50) fill.classList.add('fill-critical');
    else if (score < 80) fill.classList.add('fill-warning');
  } else {
    fill.style.width = '0%';
  }
  bar.append(fill);
  root.append(bar);
}

// renderCounts — счётчики замечаний по серьёзности.
export function renderCounts(root: HTMLElement, counts: Record<string, number>, unknownChecks: number): void {
  root.textContent = '';
  for (const [key, label] of [['critical', 'Критичные'], ['warning', 'Важные'], ['info', 'Прочие']] as const) {
    const cell = el('div', 'sec-count');
    cell.append(el('div', `severity-${key}`, `${label}`));
    cell.append(el('div', 'sec-count-value', String(counts[key] ?? 0)));
    root.append(cell);
  }
  if (unknownChecks > 0) {
    const cell = el('div', 'sec-count');
    cell.append(el('div', 'severity-unknown', 'Не определено'));
    cell.append(el('div', 'sec-count-value', String(unknownChecks)));
    root.append(cell);
  }
}

// renderGroups — список замечаний (агрегированных или сетевых).
export function renderGroups(root: HTMLElement, groups: SecurityGroup[]): void {
  root.textContent = '';
  if (groups.length === 0) {
    root.append(el('p', 'muted', 'замечаний нет'));
    return;
  }
  for (const g of groups) {
    const row = el('div', `finding severity-${g.severity}`);
    row.append(el('span', 'finding-sev', sevNames[g.severity] ?? g.severity));
    const body = el('div', 'finding-body');
    body.append(el('div', 'finding-fact', g.title));
    body.append(el('div', 'muted', `Основание: ${g.basis}`));
    body.append(el('div', 'muted', `Как исправить: ${g.advice}`));
    row.append(body);
    row.append(el('span', 'finding-where', g.where.join(', ')));
    root.append(row);
  }
}

// renderComputers — строки компьютеров с оценками.
export function renderComputers(
  root: HTMLElement,
  computers: SecuritySummary['computers'],
  onComputer: (id: string) => void,
): void {
  root.textContent = '';
  if (computers.length === 0) {
    root.append(el('p', 'muted', 'нет компьютеров с данными'));
    return;
  }
  const table = el('table', 'data-table');
  const thead = el('thead', '');
  const hr = el('tr', '');
  for (const h of ['Компьютер', 'Оценка', 'Состояние', 'Не определено']) hr.append(el('th', '', h));
  thead.append(hr);
  table.append(thead);
  const tbody = el('tbody', '');
  for (const c of computers) {
    const tr = el('tr', 'sec-computer-row');
    tr.setAttribute('data-agent', c.id);
    tr.append(el('td', '', c.hostname));
    tr.append(el('td', '', String(c.score)));
    tr.append(el('td', `severity-${c.worst}`, sevNames[c.worst] ?? c.worst));
    tr.append(el('td', '', String(c.unknown_checks)));
    tr.addEventListener('click', () => onComputer(c.id));
    tbody.append(tr);
  }
  table.append(tbody);
  root.append(table);
}

// checkLine — одна проверка карточки.
export function checkLine(chk: SecurityCheck): HTMLElement {
  const row = el('div', `sec-check sec-check-${chk.status}`);
  row.append(el('span', 'sec-check-status', checkStatusName(chk.status)));
  row.append(el('span', '', chk.id));
  if (chk.detail !== undefined) row.append(el('span', 'muted', chk.detail));
  return row;
}

// renderSecurityCard — карточка компьютера: проверки, замечания,
// слушающие порты.
export function renderSecurityCard(root: HTMLElement, card: SecurityCard, onBack: () => void): void {
  root.textContent = '';
  const head = el('div', 'sec-card-head');
  const back = el('button', 'ghost', '← Все компьютеры') as HTMLButtonElement;
  back.addEventListener('click', onBack);
  head.append(back, el('h3', '', `Безопасность: ${card.hostname}`));
  if (card.score !== null) {
    head.append(el('span', 'sec-card-score', `оценка ${card.score} / 100`));
  }
  root.append(head);
  if (card.collected_at !== undefined) {
    root.append(el('div', 'muted', `отчёт проверок: ${card.collected_at}`));
  }

  root.append(el('h4', '', 'Проверки'));
  const checksBox = el('div', 'sec-checks');
  if (card.checks.length === 0) {
    checksBox.append(el('p', 'muted', 'отчёт проверок ещё не приходил'));
  }
  for (const chk of card.checks) checksBox.append(checkLine(chk));
  root.append(checksBox);

  root.append(el('h4', '', 'Замечания'));
  const fbox = el('div', '');
  if (card.findings.length === 0) {
    fbox.append(el('p', 'muted', 'замечаний нет'));
  }
  for (const f of card.findings) {
    const row = el('div', `finding severity-${f.severity}`);
    row.append(el('span', 'finding-sev', sevNames[f.severity] ?? f.severity));
    const body = el('div', 'finding-body');
    body.append(el('div', 'finding-fact', f.fact));
    body.append(el('div', 'muted', `Основание: ${f.basis}`));
    body.append(el('div', 'muted', `Как исправить: ${f.advice}`));
    row.append(body);
    fbox.append(row);
  }
  root.append(fbox);

  if (card.ports !== undefined && card.ports.length > 0) {
    root.append(el('h4', '', `Слушающие порты (${card.ports.length})`));
    const table = el('table', 'data-table');
    const tbody = el('tbody', '');
    for (const p of card.ports) {
      const tr = el('tr', '');
      tr.append(el('td', '', p.local_address));
      tr.append(el('td', '', String(p.local_port)));
      tr.append(el('td', '', p.process ?? ''));
      tbody.append(tr);
    }
    table.append(tbody);
    root.append(table);
  }
}

// renderSecurity — весь экран.
export function renderSecurity(
  root: HTMLElement,
  summary: SecuritySummary,
  card: SecurityCard | null,
  refs: SecurityRefs,
): void {
  root.textContent = '';
  const top = el('div', 'sec-top');
  const scoreBox = el('div', 'sec-score-box');
  scoreBox.append(el('div', 'sec-score-label', 'Общая оценка'));
  const scoreHolder = el('div', 'sec-score');
  renderScore(scoreHolder, summary.score);
  scoreBox.append(scoreHolder);
  scoreBox.append(el('div', 'muted', 'Оценка считается по правилам и весам замечаний. Она не зависит от ИИ.'));
  top.append(scoreBox);
  const counts = el('div', 'sec-counts');
  renderCounts(counts, summary.counts, summary.unknown_checks);
  top.append(counts);
  root.append(top);

  root.append(el('h3', '', 'Компьютеры'));
  const computersBox = el('div', '');
  renderComputers(computersBox, summary.computers, refs.onComputer);
  root.append(computersBox);

  const cardBox = el('div', '');
  if (card !== null) {
    renderSecurityCard(cardBox, card, () => refs.onComputer(''));
  }
  root.append(cardBox);

  root.append(el('h3', '', 'Замечания'));
  const findings = el('div', '');
  renderGroups(findings, summary.findings);
  root.append(findings);

  root.append(el('h3', '', 'Сетевые устройства'));
  const network = el('div', '');
  renderGroups(network, summary.network);
  root.append(network);
  root.append(el('p', 'muted', 'Сетевые замечания — только то, что уже известно сканеру: ответы на SNMP-опрос и его метод. Новых активных проб нет.'));
}
