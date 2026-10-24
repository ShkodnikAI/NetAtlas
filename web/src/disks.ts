// Экран «Диски» (NR-009): все тома всех агентов с заполнением и
// прогнозом. Значения сервера — только как текст.

import type { DiskView } from './api';
import { forecastText, fmtBytes } from './computers';

// barFill — полоска заполнения.
export function barFill(freePct: number): HTMLElement {
  const bar = document.createElement('div');
  bar.className = 'fill-bar';
  const fill = document.createElement('div');
  fill.className = 'fill-bar-inner';
  const used = Math.max(0, Math.min(100, 100 - freePct));
  fill.style.width = `${used.toFixed(1)}%`;
  if (freePct < 10) fill.classList.add('danger');
  else if (freePct < 20) fill.classList.add('warn');
  bar.append(fill);
  return bar;
}

// diskRow — строка одного тома.
export function diskRow(d: DiskView): HTMLElement {
  const row = document.createElement('div');
  row.className = 'disk-row';
  const title = document.createElement('span');
  title.className = 'disk-title';
  title.textContent = `${d.hostname} · том ${d.drive}`;
  row.append(title);

  const meta = document.createElement('span');
  meta.className = 'muted';
  meta.textContent = `${fmtBytes(d.used_bytes)} из ${fmtBytes(d.capacity_bytes)} · свободно ${d.free_pct.toFixed(1)}%`;
  row.append(meta);

  row.append(barFill(d.free_pct));

  const forecast = document.createElement('span');
  forecast.className = 'disk-forecast';
  forecast.textContent = forecastText(d.forecast);
  row.append(forecast);
  return row;
}

// renderDisks — экран «Диски».
export function renderDisks(root: HTMLElement, list: DiskView[]): void {
  root.textContent = '';
  if (list.length === 0) {
    const p = document.createElement('p');
    p.className = 'muted';
    p.textContent = 'нет данных: отчётов с томами нет';
    root.append(p);
    return;
  }
  for (const d of list) {
    root.append(diskRow(d));
  }
}
