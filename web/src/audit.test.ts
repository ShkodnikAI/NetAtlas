// Тесты плашки целостности журнала аудита (NR-023): jsdom, без сети.

import { describe, expect, it } from 'vitest';
import { setAuditBadge } from './audit';

describe('setAuditBadge', () => {
  it('целая цепочка скрывает плашку', () => {
    const el = document.createElement('div');
    setAuditBadge(el, true);
    expect(el.hidden).toBe(true);
  });

  it('нарушенная цепочка показывает красную плашку с текстом', () => {
    const el = document.createElement('div');
    setAuditBadge(el, false);
    expect(el.hidden).toBe(false);
    expect(el.textContent).toBe('журнал аудита нарушен');
    expect(el.className).toContain('audit-badge');
  });
});
