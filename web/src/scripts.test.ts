// Тесты экрана «Скрипты и тесты» (NR-011): счётчики этапов, кнопки
// только допустимых переходов, подтверждение подписи вводом,
// фильтр журнала.

import { describe, expect, it } from 'vitest';
import {
  allowedActions,
  filterScriptAudit,
  nextStatus,
  renderStages,
  validateSignInput,
  type AuditEntry,
} from './scripts';

// nextStatus идёт по цепочке и заканчивается на released.
describe('nextStatus', () => {
  it('проходит цепочку по шагам', () => {
    expect(nextStatus('draft')).toBe('checked');
    expect(nextStatus('checked')).toBe('tested');
    expect(nextStatus('tested')).toBe('signed');
    expect(nextStatus('signed')).toBe('pilot');
    expect(nextStatus('pilot')).toBe('released');
  });

  it('у released следующего нет, rejected вне цепочки', () => {
    expect(nextStatus('released')).toBeNull();
    expect(nextStatus('rejected')).toBeNull();
    expect(nextStatus('неведомо')).toBeNull();
  });
});

// Кнопки только для допустимых переходов.
describe('allowedActions', () => {
  it('draft показывает только переход к проверке и возврат', () => {
    const acts = allowedActions('draft');
    expect(acts.map((a) => a.to)).toEqual(['checked', 'rejected']);
  });

  it('tested показывает подпись, а не статусный переход', () => {
    const acts = allowedActions('tested');
    expect(acts.filter((a) => a.to === 'signed').map((a) => a.kind)).toEqual(['sign']);
    // Нет кнопки статусного перехода в signed.
    expect(acts.filter((a) => a.kind === 'status' && a.to === 'signed')).toHaveLength(0);
  });

  it('released не показывает переход вперёд, но показывает возврат', () => {
    const acts = allowedActions('released');
    expect(acts.map((a) => a.to)).toEqual(['rejected']);
  });

  it('rejected не показывает ничего', () => {
    expect(allowedActions('rejected')).toHaveLength(0);
  });
});

// Подтверждение подписи: имя и хэш должны совпасть точно.
describe('validateSignInput', () => {
  const sha = 'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233';

  it('верное имя и хэш проходят', () => {
    expect(validateSignInput('Скрипт', 'Скрипт', sha, sha)).toBe('');
    // Регистр хэша и разделители не важны.
    expect(validateSignInput('Скрипт', 'Скрипт', sha.toUpperCase(), sha)).toBe('');
    expect(validateSignInput('Скрипт', 'Скрипт', sha.slice(0, 16) + ':' + sha.slice(16), sha)).toBe('');
  });

  it('чужое имя отвергается', () => {
    expect(validateSignInput('Другое', 'Скрипт', sha, sha)).toContain('Имя');
  });

  it('чужой хэш отвергается', () => {
    expect(validateSignInput('Скрипт', 'Скрипт', 'ff' + sha.slice(2), sha)).toContain('Хэш');
  });

  it('пустой ввод отвергается', () => {
    expect(validateSignInput('', 'Скрипт', sha, sha)).toContain('Имя');
    expect(validateSignInput('Скрипт', 'Скрипт', '', sha)).toContain('Хэш');
  });
});

// Счётчики этапов: шесть карточек, счётчик по статусу.
describe('renderStages', () => {
  it('рисует шесть этапов с счётчиками', () => {
    const root = document.createElement('div');
    renderStages(root, { draft: 2, checked: 1, signed: 3 });
    expect(root.children).toHaveLength(6);
    const text = root.textContent ?? '';
    expect(text).toContain('Черновик');
    expect(text).toContain('Раскатка');
    // Счётчики отсутствующих статусов — нули, не undefined.
    expect(text).not.toContain('undefined');
  });
});

// Журнал экрана: только действия конвейера.
describe('filterScriptAudit', () => {
  it('фильтрует действия конвейера', () => {
    const entries: AuditEntry[] = [
      { id: 1, ts: '2026-10-24T10:00:00Z', actor: 'owner', action: 'script_create', target: 'А', result: 'ok' },
      { id: 2, ts: '2026-10-24T10:01:00Z', actor: 'owner', action: 'add_device', target: 'dev', result: 'ok' },
      { id: 3, ts: '2026-10-24T10:02:00Z', actor: 'owner', action: 'script_sign', target: 'А', result: 'ok' },
      { id: 4, ts: '2026-10-24T10:03:00Z', actor: 'agent-api', action: 'job_dispatch', target: 'А', result: 'ok' },
      { id: 5, ts: '2026-10-24T10:04:00Z', actor: 'agent-api', action: 'job_autostop', target: 'А', result: 'fail' },
      { id: 6, ts: '2026-10-24T10:05:00Z', actor: 'owner', action: 'save_scan', target: 'scan', result: 'ok' },
    ];
    const kept = filterScriptAudit(entries);
    expect(kept.map((e) => e.action)).toEqual(['script_create', 'script_sign', 'job_dispatch', 'job_autostop']);
  });

  it('пустой список даёт пустой результат', () => {
    expect(filterScriptAudit([])).toHaveLength(0);
  });
});
