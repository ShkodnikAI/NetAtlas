// Тесты экрана «Активность» (NR-012): KPI, фраза подтверждения,
// прозрачность, топы приложений/доменов.

import { describe, expect, it } from 'vitest';
import {
  CONFIRMATION_PHRASE,
  fmtSecs,
  kpiCards,
  notCollectedList,
  topNamed,
  validateEnableInput,
} from './activity';
import type { ActivitySummary } from './api';

// fmtSecs: часы и минуты.
describe('fmtSecs', () => {
  it('переводит секунды в человекочитаемый вид', () => {
    expect(fmtSecs(0)).toBe('0 мин');
    expect(fmtSecs(59)).toBe('0 мин');
    expect(fmtSecs(60)).toBe('1 мин');
    expect(fmtSecs(45 * 60)).toBe('45 мин');
    expect(fmtSecs(3 * 3600 + 25 * 60)).toBe('3 ч 25 мин');
  });
});

// KPI: активность, простой, ПК со сбором, агрегаты.
describe('kpiCards', () => {
  it('считает долю активности и количество ПК', () => {
    const s: ActivitySummary = {
      from: '', to: '',
      totals: { active_sec: 2700, idle_sec: 900, reports: 12 },
      accounts: [], apps: [], domains: [],
    };
    const k = kpiCards(s, 3);
    expect(k).toHaveLength(4);
    const [activity, idle, computers, reports] = k;
    expect(activity?.value).toBe('45 мин');
    expect(activity?.note).toContain('75%');
    expect(computers?.value).toBe('3');
    expect(reports?.value).toBe('12');
    expect(idle?.label).toContain('Простой');
  });

  it('без данных доля не делит на ноль', () => {
    const s: ActivitySummary = {
      from: '', to: '', totals: {}, accounts: [], apps: [], domains: [],
    };
    const k = kpiCards(s, 0);
    expect(k[0]?.value).toBe('0 мин');
    expect(k[0]?.note).toContain('0%');
  });
});

// Топ имён: сортировка и предел.
describe('topNamed', () => {
  it('сортирует по убыванию и обрезает', () => {
    const got = topNamed([{ name: 'a', value: 1 }, { name: 'c', value: 5 }, { name: 'b', value: 3 }], 2);
    expect(got.map((x) => x.name)).toEqual(['c', 'b']);
    expect(topNamed([{ name: 'a', value: 1 }], 5)).toHaveLength(1);
  });
});

// Валидация включения: точная фраза и корректный идентификатор.
describe('validateEnableInput', () => {
  it('верная фраза и agent: проходят', () => {
    expect(validateEnableInput('agent:abc', CONFIRMATION_PHRASE)).toBe('');
  });
  it('неверная фраза и чужой идентификатор отвергаются', () => {
    expect(validateEnableInput('agent:abc', 'уведомлены')).toContain('точную фразу');
    expect(validateEnableInput('abc', CONFIRMATION_PHRASE)).toContain('agent:');
    expect(validateEnableInput('', CONFIRMATION_PHRASE)).toContain('agent:');
  });
});

// Прозрачность: список «не собирается» перечисляет запрещённое.
describe('transparency', () => {
  it('не собирается: клавиши, переписка, пароли, адреса, скриншоты', () => {
    for (const word of ['Нажатия клавиш', 'переписки', 'пароли', 'адреса страниц', 'скриншоты']) {
      expect(notCollectedList).toContain(word);
    }
  });
});
