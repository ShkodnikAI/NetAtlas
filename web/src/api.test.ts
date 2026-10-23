// Тесты клиента API: без реальных сетевых запросов (fetch подменён).

import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, NetatlasApi, humanize } from './api';

function mockFetch(status: number, body: string): ReturnType<typeof vi.fn> {
  const fn = vi.fn(async () =>
    new Response(body, { status, headers: { 'Content-Type': 'application/json' } }),
  );
  vi.stubGlobal('fetch', fn);
  return fn;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('NetatlasApi', () => {
  it('посылает Bearer-токен и парсит граф', async () => {
    const fn = mockFetch(200, JSON.stringify({
      nodes: [{ id: '00:00:00:00:00:01', kind: 'switch', label: 'sw', manual: false, verified: true }],
      links: [],
    }));
    const api = new NetatlasApi();
    api.setToken('тест-токен-длиной-больше-24-символов');
    const g = await api.topology();
    expect(g.nodes).toHaveLength(1);
    expect(g.nodes[0]?.kind).toBe('switch');
    const init = fn.mock.calls[0]?.[1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toContain('Bearer ');
  });

  it('401 сбрасывает токен и зовёт onUnauthorized', async () => {
    mockFetch(401, '{"error":"требуется авторизация"}');
    const api = new NetatlasApi();
    api.setToken('тест-токен-длиной-больше-24-символов');
    let asked = 0;
    api.onUnauthorized = () => {
      asked++;
    };
    await expect(api.topology()).rejects.toThrow(ApiError);
    expect(asked).toBe(1);
    expect(api.hasToken()).toBe(false);
  });

  it('409 даёт понятный текст без кода в теле ошибки сервера', async () => {
    mockFetch(409, '{}');
    const api = new NetatlasApi();
    await expect(api.deleteDevice('manual:1')).rejects.toThrow('элемент не ручной');
  });

  it('addDevice шлёт kind и name в JSON', async () => {
    const fn = mockFetch(201, '{"id":"manual:00000001"}');
    const api = new NetatlasApi();
    await api.addDevice('printer', 'принтер');
    const [path, init] = fn.mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/api/devices');
    expect(JSON.parse(init.body as string)).toEqual({ kind: 'printer', name: 'принтер' });
  });
});

describe('humanize', () => {
  it('отдаёт текст из тела ошибки сервера', () => {
    expect(humanize(400, '{"error":"адреса вне подсетей"}')).toBe('адреса вне подсетей');
  });
  it('401 без тела даёт стандартную подсказку', () => {
    expect(humanize(401, '')).toContain('401');
  });
  it('не выделяет данные из не-JSON тела', () => {
    expect(humanize(500, '<html> Internal </html>')).toContain('500');
  });
});
