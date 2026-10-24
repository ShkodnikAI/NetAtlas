// Экран «Компьютеры» (NR-009): сводка по агентам и карточка с
// вкладками. Все значения из сервера вставляются как текст
// (textContent), не как разметка.

import type { ComputerCard, ComputerSummary, Finding } from './api';

// el — элемент с классом и текстом.
function el(tag: string, cls: string, text?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls !== '') e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

const severityNames: Record<string, string> = {
  critical: 'критично',
  warning: 'предупреждение',
  info: 'информация',
};

// chipSeverity — плашка серьёзности.
export function chipSeverity(severity: string): HTMLElement {
  const chip = el('span', `chip severity-${severity}`, severityNames[severity] ?? severity);
  return chip;
}

// findingsLine — краткая строка счётчиков замечаний.
export function findingsLine(summary: ComputerSummary): string {
  if (!summary.inventory_at) return 'нет данных';
  const f = summary.findings ?? {};
  const parts: string[] = [];
  if ((f['critical'] ?? 0) > 0) parts.push(`критично: ${f['critical']}`);
  if ((f['warning'] ?? 0) > 0) parts.push(`предупреждений: ${f['warning']}`);
  if ((f['info'] ?? 0) > 0) parts.push(`информация: ${f['info']}`);
  if (parts.length === 0) return 'замечаний нет';
  return parts.join(', ');
}

// forecastText — «заполнится через N дней» или причина.
export function forecastText(f: { days_to_full?: number; insufficient?: string }): string {
  if (f.days_to_full !== undefined) {
    return `заполнится через ${f.days_to_full} дн.`;
  }
  if (f.insufficient !== undefined && f.insufficient !== '') {
    return `прогноз: нет (${f.insufficient})`;
  }
  return 'прогноз: не переполнится';
}

// fmtBytes — байты в ГБ (одна десятичная).
export function fmtBytes(b?: number | string): string {
  const n = typeof b === 'string' ? Number(b) : b;
  if (n === undefined || Number.isNaN(n) || n <= 0) return '—';
  return `${(n / 2 ** 30).toFixed(1)} ГБ`;
}

// renderComputers — список компьютеров (сводка).
export function renderComputers(root: HTMLElement, list: ComputerSummary[], onOpen: (id: string) => void): void {
  root.textContent = '';
  if (list.length === 0) {
    root.append(el('p', 'muted', 'нет данных: агентов нет'));
    return;
  }
  const table = el('table', 'data-table');
  const thead = el('thead', '');
  const hr = el('tr', '');
  for (const h of ['Компьютер', 'Статус', 'Замечания', 'Диски', 'Отчёт от']) {
    hr.append(el('th', '', h));
  }
  thead.append(hr);
  table.append(thead);
  const tbody = el('tbody', '');
  for (const c of list) {
    const tr = el('tr', 'row-click');
    tr.append(el('td', '', c.hostname !== '' ? c.hostname : c.id));
    tr.append(el('td', '', c.status));
    tr.append(el('td', '', findingsLine(c)));
    const diskCell = el('td', '');
    if (c.worst_days_to_full !== undefined) {
      diskCell.textContent = `заполнится через ${c.worst_days_to_full} дн.`;
    } else {
      diskCell.textContent = '—';
    }
    tr.append(diskCell);
    tr.append(el('td', '', c.inventory_at ? new Date(c.inventory_at).toLocaleString() : '—'));
    tr.addEventListener('click', () => onOpen(c.id));
    tbody.append(tr);
  }
  table.append(tbody);
  root.append(table);
}

// tab — вкладка карточки.
export function tabButton(id: string, title: string): HTMLButtonElement {
  const b = document.createElement('button');
  b.className = 'tab';
  b.type = 'button';
  b.textContent = title;
  b.dataset.tab = id;
  return b;
}

// findingRow — строка замечания: серьёзность, факт, совет.
export function findingRow(f: Finding): HTMLElement {
  const div = el('div', `finding severity-${f.severity}`);
  div.append(chipSeverity(f.severity));
  div.append(el('span', 'finding-fact', f.fact));
  div.append(el('div', 'muted', `рекомендация: ${f.advice}`));
  div.append(el('div', 'muted', `источник: ${f.source} · правило: ${f.rule_id}`));
  return div;
}

// kvRow — пара «подпись: значение» (значение — текст).
export function kvRow(label: string, value: string): HTMLElement {
  const row = el('div', 'kv');
  row.append(el('span', 'kv-label', label));
  row.append(el('span', 'kv-value', value === '' ? '—' : value));
  return row;
}

// renderComputerCard — карточка компьютера с вкладками.
export function renderComputerCard(root: HTMLElement, card: ComputerCard, onBack: () => void): void {
  root.textContent = '';
  const head = el('div', 'card-head');
  const back = el('button', 'back', '← К списку') as HTMLButtonElement;
  back.type = 'button';
  back.addEventListener('click', onBack);
  head.append(back, el('h2', '', card.hostname !== '' ? card.hostname : card.id));
  root.append(head);

  if (!card.inventory_at || card.inventory === undefined) {
    root.append(el('p', 'muted', 'нет данных: агент ещё не присылал инвентарь'));
    return;
  }
  root.append(el('p', 'subtitle', `отчёт от ${new Date(card.inventory_at).toLocaleString()}`));

  const inv = card.inventory;
  const tabs = el('div', 'tabs2');
  const pages: Record<string, HTMLElement> = {
    overview: el('div', 'tabpage2 active'),
    hardware: el('div', 'tabpage2'),
    disks: el('div', 'tabpage2'),
    drivers: el('div', 'tabpage2'),
    programs: el('div', 'tabpage2'),
    findings: el('div', 'tabpage2'),
  };
  const titles: [string, string][] = [
    ['overview', 'Обзор'], ['hardware', 'Железо'], ['disks', 'Диски'],
    ['drivers', 'Драйверы'], ['programs', 'Программы'], ['findings', 'Замечания'],
  ];
  for (const [id, title] of titles) {
    const b = tabButton(id, title);
    b.addEventListener('click', () => {
      tabs.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
      b.classList.add('active');
      for (const [pid, p] of Object.entries(pages)) {
        p.classList.toggle('active', pid === id);
      }
    });
    tabs.append(b);
  }
  root.append(tabs);

  // Обзор: ОС, прогнозы, сводка.
  const ov = pages['overview'] as HTMLElement;
  ov.append(kvRow('Операционная система', inv.os?.caption ?? ''));
  ov.append(kvRow('Сборка', inv.os?.build_number ?? ''));
  ov.append(kvRow('Архитектура', inv.os?.architecture ?? ''));
  ov.append(kvRow('Последнее обновление', inv.os?.latest_hotfix ?? ''));
  for (const [drive, f] of Object.entries(card.forecasts ?? {})) {
    ov.append(kvRow(`Том ${drive}`, forecastText(f)));
  }
  const errs = inv.collector_errors ?? [];
  if (errs.length > 0) {
    ov.append(kvRow('Ошибки сборщиков', String(errs.length)));
  }

  // Железо.
  const hw = pages['hardware'] as HTMLElement;
  hw.append(kvRow('ОЗУ', fmtBytes(inv.hardware?.total_physical_memory)));
  for (const cpu of inv.hardware?.cpus ?? []) {
    hw.append(kvRow('Процессор', `${cpu.name ?? '—'} (${cpu.cores ?? '?'} ядер)`));
  }
  for (const m of inv.hardware?.memory_modules ?? []) {
    hw.append(kvRow('Модуль ОЗУ', `${m.slot ?? '—'}: ${fmtBytes(m.capacity)}, ${m.speed_mhz ?? '?'} МГц`));
  }
  hw.append(kvRow('Плата', `${inv.hardware?.base_board?.manufacturer ?? ''} ${inv.hardware?.base_board?.product ?? ''}`.trim()));
  hw.append(kvRow('BIOS', `${inv.hardware?.bios?.manufacturer ?? ''} ${inv.hardware?.bios?.version ?? ''}`.trim()));

  // Диски.
  const disks = pages['disks'] as HTMLElement;
  for (const d of inv.disks?.disks ?? []) {
    disks.append(kvRow('Диск', `${d.friendly_name ?? '—'}, ${fmtBytes(d.size)}, ${d.health ?? '—'}`));
  }
  for (const v of inv.disks?.volumes ?? []) {
    disks.append(kvRow(`Том ${v.drive_letter ?? '?'}`, `${fmtBytes(v.size)}, свободно ${fmtBytes(v.size_remaining)}`));
  }

  // Драйверы и программы.
  for (const d of inv.drivers ?? []) {
    (pages['drivers'] as HTMLElement).append(kvRow(d.device_name ?? '—', `${d.version ?? '—'} (${d.date ?? '—'})`));
  }
  for (const p of inv.programs ?? []) {
    (pages['programs'] as HTMLElement).append(kvRow(p.name ?? '—', `${p.version ?? '—'} · ${p.publisher ?? '—'}`));
  }

  // Замечания.
  const fnd = pages['findings'] as HTMLElement;
  const list = card.findings ?? [];
  if (list.length === 0) {
    fnd.append(el('p', 'muted', 'замечаний нет'));
  }
  for (const f of list) {
    fnd.append(findingRow(f));
  }

  for (const p of Object.values(pages)) {
    root.append(p);
  }
}
