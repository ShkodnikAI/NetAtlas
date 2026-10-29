// Тесты сигналов внимания (NR-033 п.4, NR-037 п.5): группировка
// однотипных сигналов «новое устройство» в панели, счётчик бейджа,
// подавление счётчика решений на узлах.
import { describe, expect, it } from 'vitest';

import {
  attentionBadgeCount,
  newDeviceGroup,
  renderAttentionPanel,
  sortSignals,
  withGroupedDecisions,
  type SignalStatus,
} from './signals';
import type { MapSignal } from './api';

// Среда jsdom включается конфигурацией vitest (environment: jsdom).

function sig(
  id: string,
  kind: string,
  status: string,
  decision: boolean,
  text = '',
): MapSignal {
  return { device_id: id, kind, status, decision, text } as MapSignal;
}

const UNKNOWN_NEW = [
  sig('02:00:00:00:00:01', 'unknown_new', 'attention', true, 'Новое устройство'),
  sig('02:00:00:00:00:02', 'unknown_new', 'attention', true, 'Новое устройство'),
  sig('02:00:00:00:00:03', 'unknown_new', 'attention', true, 'Новое устройство'),
];

describe('newDeviceGroup (NR-037 п.5)', () => {
  it('два и более сигналов «новое устройство» образуют группу', () => {
    const { group, rest } = newDeviceGroup(UNKNOWN_NEW);
    expect(group).toHaveLength(3);
    expect(rest).toHaveLength(0);
  });

  it('одиночный сигнал остаётся отдельной строкой', () => {
    const { group, rest } = newDeviceGroup([UNKNOWN_NEW[0] as MapSignal]);
    expect(group).toHaveLength(0);
    expect(rest).toHaveLength(1);
  });

  it('сигналы без решения и не «новые устройства» не группируются', () => {
    const signals: MapSignal[] = [
      sig('02:00:00:00:00:01', 'unknown_new', 'attention', false),
      sig('02:00:00:00:00:02', 'no_response', 'offline', false),
      sig('', 'audit_gap', 'problem', false),
    ];
    const { group, rest } = newDeviceGroup(signals);
    expect(group).toHaveLength(0);
    expect(rest).toHaveLength(3);
  });
});

describe('attentionBadgeCount (NR-037 п.5)', () => {
  it('группа считается одним сигналом', () => {
    const signals: MapSignal[] = [
      ...UNKNOWN_NEW,
      sig('02:00:00:00:00:09', 'no_response', 'offline', false),
    ];
    expect(attentionBadgeCount(signals)).toBe(2);
  });

  it('без группы счётчик равен числу сигналов', () => {
    expect(attentionBadgeCount([UNKNOWN_NEW[0] as MapSignal])).toBe(1);
  });
});

describe('withGroupedDecisions (NR-037 п.5)', () => {
  it('у узлов группы счётчик решений скрыт, статус остаётся', () => {
    const statuses = new Map<string, SignalStatus>([
      ['02:00:00:00:00:01', { status: 'attention', decisions: 1 }],
      ['02:00:00:00:00:02', { status: 'attention', decisions: 1 }],
      ['02:00:00:00:00:09', { status: 'offline', decisions: 0 }],
    ]);
    const out = withGroupedDecisions(statuses, UNKNOWN_NEW);
    expect(out.get('02:00:00:00:00:01')).toEqual({ status: 'attention', decisions: 0 });
    expect(out.get('02:00:00:00:00:02')).toEqual({ status: 'attention', decisions: 0 });
    expect(out.get('02:00:00:00:00:09')).toEqual({ status: 'offline', decisions: 0 });
  });

  it('узел с другим решением показывает настоящий счётчик', () => {
    const statuses = new Map<string, SignalStatus>([
      ['02:00:00:00:00:01', { status: 'attention', decisions: 2 }],
    ]);
    const signals: MapSignal[] = [
      ...UNKNOWN_NEW,
      sig('02:00:00:00:00:01', 'security', 'problem', true),
    ];
    const out = withGroupedDecisions(statuses, signals);
    expect(out.get('02:00:00:00:00:01')).toEqual({ status: 'attention', decisions: 2 });
  });

  it('без группы статусы не трогаются', () => {
    const statuses = new Map<string, SignalStatus>([
      ['02:00:00:00:00:01', { status: 'attention', decisions: 1 }],
    ]);
    const out = withGroupedDecisions(statuses, [UNKNOWN_NEW[0] as MapSignal]);
    expect(out.get('02:00:00:00:00:01')).toEqual({ status: 'attention', decisions: 1 });
  });
});

describe('renderAttentionPanel (NR-037 п.5)', () => {
  it('группа показывается одной строкой, отдельные строки скрыты', () => {
    const panel = document.createElement('div');
    const signals: MapSignal[] = [
      ...UNKNOWN_NEW,
      sig('02:00:00:00:00:09', 'no_response', 'offline', false),
    ];
    renderAttentionPanel(panel, signals, [], { onFocus: () => {} });
    const head = panel.querySelector('.attention-group-head');
    expect(head).not.toBeNull();
    expect(head?.querySelector('.attention-head')?.textContent).toBe('Новые устройства: 3');
    // Отдельные строки группы скрыты; строка другого сигнала видна.
    const list = panel.querySelector('.attention-group-list') as HTMLElement;
    expect(list.hidden).toBe(true);
    expect(list.querySelectorAll('.attention-row')).toHaveLength(3);
    // На верхнем уровне панели — группа и строка другого сигнала.
    const topRows = [...panel.children].filter((el) =>
      el.classList.contains('attention-row'),
    ) as HTMLElement[];
    expect(topRows).toHaveLength(1);
    expect(topRows[0]?.dataset.kind).toBe('no_response');
  });

  it('раскрытие показывает список и кнопки приёма всей группы', () => {
    const panel = document.createElement('div');
    renderAttentionPanel(panel, UNKNOWN_NEW, [], { onFocus: () => {} });
    const head = panel.querySelector('.attention-group-head') as HTMLButtonElement;
    head.click();
    expect(head.getAttribute('aria-expanded')).toBe('true');
    const actions = panel.querySelector('.attention-group-actions') as HTMLElement;
    const list = panel.querySelector('.attention-group-list') as HTMLElement;
    expect(actions.hidden).toBe(false);
    expect(list.hidden).toBe(false);
    const buttons = [...actions.querySelectorAll('.attention-accept')] as HTMLButtonElement[];
    expect(buttons.map((b) => b.textContent)).toEqual([
      'Принять все как Моё',
      'Принять все как Гость',
    ]);
    // Повторный клик сворачивает.
    head.click();
    expect(head.getAttribute('aria-expanded')).toBe('false');
    expect((panel.querySelector('.attention-group-actions') as HTMLElement).hidden).toBe(true);
  });

  it('«Принять все» передаёт список устройств и класс обработчику', () => {
    const panel = document.createElement('div');
    let got: { ids: string[]; klass: string } | null = null;
    renderAttentionPanel(panel, UNKNOWN_NEW, [], {
      onFocus: () => {},
      onAcceptAll: (ids, klass) => {
        got = { ids, klass };
      },
    });
    const head = panel.querySelector('.attention-group-head') as HTMLButtonElement;
    head.click();
    const buttons = [...panel.querySelectorAll('.attention-accept')] as HTMLButtonElement[];
    buttons[1]?.click();
    expect(got).toEqual({
      ids: ['02:00:00:00:00:01', '02:00:00:00:00:02', '02:00:00:00:00:03'],
      klass: 'guest',
    });
  });

  it('строки группы кликабельны — фокус узла работает', () => {
    const panel = document.createElement('div');
    let focused = '';
    renderAttentionPanel(panel, UNKNOWN_NEW, [], {
      onFocus: (id) => {
        focused = id;
      },
    });
    const head = panel.querySelector('.attention-group-head') as HTMLButtonElement;
    head.click();
    const first = panel.querySelector('.attention-group-list .attention-row') as HTMLButtonElement;
    first.click();
    expect(focused).toBe('02:00:00:00:00:01');
  });

  it('строки вне группы идут по важности: проблема выше группы', () => {
    const panel = document.createElement('div');
    const signals: MapSignal[] = [
      ...UNKNOWN_NEW,
      sig('', 'audit_gap', 'problem', false),
    ];
    renderAttentionPanel(panel, signals, [], { onFocus: () => {} });
    const first = panel.firstElementChild as HTMLElement;
    expect(first.classList.contains('attention-group')).toBe(false);
    expect(first.dataset.kind).toBe('audit_gap');
    // Группа сразу после проблемной строки.
    const second = panel.children[1] as HTMLElement;
    expect(second.classList.contains('attention-group')).toBe(true);
  });

  it('сортировка внутри панели остаётся детерминированной (NR-033)', () => {
    const signals: MapSignal[] = [
      sig('02:00:00:00:00:09', 'no_response', 'offline', false, 'не отвечает'),
      sig('', 'audit_gap', 'problem', false, 'разрыв журнала'),
    ];
    const sorted = sortSignals(signals);
    expect(sorted[0]?.kind).toBe('audit_gap');
    expect(sorted[1]?.kind).toBe('no_response');
  });
});
