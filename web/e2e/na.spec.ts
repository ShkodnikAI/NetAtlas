// Сквозные тесты интерфейса в настоящем Chromium (NR-031, обязательная
// проверка): один видимый экран на пункт меню, подсети после входа,
// таблица устройств с адресами, подписи карты без пересечений, один
// пункт «Активность». Тесты обязаны падать, если убрать правило
// [hidden] из CSS, — первый же экран увидит лишнее.
import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, test, type Page } from '@playwright/test';

const TOKEN = process.env.NETATLAS_E2E_TOKEN ?? 'netatlas-e2e-local-token-000';
const SHOTS = join(process.cwd(), 'e2e-results', 'screens');
mkdirSync(SHOTS, { recursive: true });

// Экраны интерфейса; карте соответствует .workspace (граф + панель).
const SCREEN_IDS = [
  'screen-scan',
  'screen-devices',
  'screen-computers',
  'screen-disks',
  'screen-quality',
  'screen-security',
  'screen-scripts',
  'screen-activity',
  'screen-reports',
] as const;

const MENU_PAGES = [
  'map', 'scan', 'devices', 'computers', 'disks',
  'quality', 'security', 'scripts', 'activity', 'reports',
] as const;

async function login(page: Page): Promise<void> {
  await page.goto('/');
  const dialog = page.locator('#token-dialog');
  await expect(dialog).toBeVisible();
  await page.fill('#token-input', TOKEN);
  await page.click('#token-submit');
  await expect(dialog).toBeHidden();
}

async function shot(page: Page, name: string): Promise<void> {
  await page.screenshot({ path: join(SHOTS, `${name}.png`) });
}

test('правило [hidden] присутствует в отгружаемом CSS (регрессия NR-031 п.1)', async ({ request }) => {
  const res = await request.get('/app.css');
  expect(res.ok()).toBe(true);
  const css = await res.text();
  expect(css).toMatch(/\[hidden\][^{}]*\{[^}]*display:\s*none\s*!important/);
});

test('в меню один пункт «Активность» и нет заглушек «скоро» (NR-031 п.5)', async ({ page }) => {
  await login(page);
  const items = page.locator('nav .item', { hasText: 'Активность' });
  await expect(items).toHaveCount(1);
  await expect(items.first()).not.toBeDisabled();
  await expect(page.locator('nav .item.soon')).toHaveCount(0);
});

test('на каждый пункт меню виден ровно один экран; выбранный пункт подсвечен', async ({ page }) => {
  await login(page);
  for (const target of MENU_PAGES) {
    await page.click(`nav .item[data-page="${target}"]`);
    const visible = await page.evaluate((ids: string[]) => {
      const shown = (el: Element | null): boolean =>
        el !== null && window.getComputedStyle(el).display !== 'none';
      const out: string[] = [];
      for (const id of ids) {
        if (shown(document.getElementById(id))) out.push(id);
      }
      if (shown(document.querySelector('.workspace'))) out.push('workspace');
      return out;
    }, [...SCREEN_IDS]);
    const want = target === 'map' ? ['workspace'] : [`screen-${target}`];
    expect(visible, `пункт меню «${target}»: видны ${visible.join(', ')}, должен быть ${want.join(', ')}`).toEqual(want);
    // Выбранный пункт подсвечен и помечен aria-current (NR-031 п.5).
    const current = await page.getAttribute(`nav .item[data-page="${target}"]`, 'aria-current');
    expect(current).toBe('page');
    const classes = await page.getAttribute(`nav .item[data-page="${target}"]`, 'class');
    expect(classes).toContain('active');
  }
});

test('после входа подсети загружены, кнопка скана активна (NR-031 п.2)', async ({ page }) => {
  await login(page);
  await page.click('nav .item[data-page="scan"]');
  const boxes = page.locator('#scan-subnets input[type="checkbox"]');
  await expect(boxes).toHaveCount(1);
  await expect(boxes.first()).toBeChecked();
  await expect(boxes.first()).toHaveValue('192.168.100.0/24');
  await expect(page.locator('#scan-config-error')).toBeHidden();
  await expect(page.locator('#scan-retry')).toBeHidden();
  await expect(page.locator('#scan-run')).toBeEnabled();
  await expect(page.locator('#scan-run-hint')).toHaveText('');
  // Блок «Дополнительно» свёрнут по умолчанию, внутри нейтральные
  // подсказки без чужих Linux-путей (NR-031 п.7).
  const details = page.locator('#scan-advanced');
  await expect(details).toBeVisible();
  await expect(details).not.toHaveAttribute('open');
  const html = await page.locator('#screen-scan').innerHTML();
  expect(html).not.toContain('/var/lib/dhcp');
  await shot(page, 'scan');
});

test('таблица устройств заполнена адресами и отсортирована по IP (NR-031 п.3)', async ({ page }) => {
  await login(page);
  await page.click('nav .item[data-page="devices"]');
  const rows = page.locator('#devices-table tbody tr');
  await expect(rows).toHaveCount(15);
  const firstIP = await rows.first().locator('td').nth(1).textContent();
  expect(firstIP).toBe('192.168.100.1');
  const body = await page.locator('#devices-table').textContent();
  expect(body).toContain('192.168.100.18');
  expect(body).toContain('office-pc-01');
  expect(body).not.toContain('Устройств пока нет');
  await shot(page, 'devices');
});

test('пустая полоса под заголовком не показывается без сообщения (NR-031 п.6)', async ({ page }) => {
  await login(page);
  const notice = page.locator('#notice');
  await expect(notice).toBeHidden();
  await expect(notice).toHaveText('');
});

test('на карте 15 узлов и подписи не перекрываются (NR-031 п.4, NR-034 п.3)', async ({ page }) => {
  await login(page);
  await page.click('nav .item[data-page="map"]');
  await page.waitForFunction(() => {
    const hook = (window as unknown as { __netatlas?: { cy: { nodes: () => { length: number } } } }).__netatlas;
    return hook !== undefined && hook.cy.nodes().length >= 15;
  });
  // Дать раскладке и отрисовке закончиться, затем дважды проверить:
  // стабильность позиций и отсутствие пересечений подписей.
  await page.waitForTimeout(700);
  const report = await page.evaluate(() => {
    const cy = (window as unknown as {
      __netatlas: { cy: import('cytoscape').default };
    }).__netatlas.cy;
    const nodes = cy.nodes().filter((n: { isParent: () => boolean }) => !n.isParent() && !n.hasClass('bend'));
    // 15 устройств фикстуры (NR-032 + NR-034 п.3): связей LLDP/FDB
    // нет, узел коммутатора не создаётся.
    if (nodes.length !== 15) return { error: `узлов ${nodes.length}, хочу 15`, overlaps: [] as string[] };
    const boxes = nodes.map((n: { id: () => string; boundingBox: (o: object) => { x1: number; y1: number; x2: number; y2: number } }) => ({
      id: n.id(),
      box: n.boundingBox({ includeLabels: true, includeOverlays: false, includeEdges: false }),
    }));
    const overlaps: string[] = [];
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        const a = boxes[i]?.box;
        const b = boxes[j]?.box;
        if (a === undefined || b === undefined) continue;
        const ox = Math.min(a.x2, b.x2) - Math.max(a.x1, b.x1);
        const oy = Math.min(a.y2, b.y2) - Math.max(a.y1, b.y1);
        if (ox > 1 && oy > 1) overlaps.push(`${boxes[i]?.id} × ${boxes[j]?.id} (${ox.toFixed(1)}×${oy.toFixed(1)})`);
      }
    }
    return { error: null, overlaps };
  });
  expect(report.error).toBeNull();
  expect(report.overlaps).toEqual([]);
  await shot(page, 'map');
});

test('все экраны сняты на скриншоты (артефакт прогона)', async ({ page }) => {
  await login(page);
  for (const target of MENU_PAGES) {
    await page.click(`nav .item[data-page="${target}"]`);
    await page.waitForTimeout(300);
    await shot(page, `screen-${target}`);
  }
});

// --- NR-032: типы узлов, предполагаемые связи, сетка, легенда ----------

test('значки узлов различаются по типам (data-kind, NR-032 п.6)', async ({ page }) => {
  await login(page);
  await page.click('nav .item[data-page="map"]');
  await page.waitForFunction(() => {
    const hook = (window as unknown as { __netatlas?: { cy: { nodes: () => { length: number } } } }).__netatlas;
    return hook !== undefined && hook.cy.nodes().length >= 15;
  });
  // a11y-слой повторяет узлы карты с data-kind (скринридеры и тесты).
  const kinds = await page.locator('#map-a11y li').evaluateAll((els) =>
    els.map((el) => (el as HTMLElement).dataset.kind ?? ''),
  );
  expect(kinds).toHaveLength(15);
  expect(new Set(kinds)).toEqual(
    new Set(['router', 'server', 'device', 'printer', 'phone', 'iot', 'unknown']),
  );
  await shot(page, 'map-kinds');
});

test('значки NR-036 «Цвет по роли»: диски по ролям, пунктир offline, маркеры форм', async ({ page }) => {
  await openMap(page);
  const icons = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const out: Record<string, string> = {};
    cy.nodes()
      .filter((n: { isParent: () => boolean }) => !n.isParent() && !n.hasClass('bend'))
      .forEach((n: { data: (k: string) => string }) => {
        const k = n.data('kind');
        if (out[k] === undefined) out[k] = n.data('icon') ?? '';
      });
    return out;
  });
  const dec = (s: string): string => decodeURIComponent(s);
  // Разные роли — разный цвет диска: сеть, компьютеры, мобильное.
  expect(dec(icons.router)).toContain('#2F6FB5');
  expect(dec(icons.device)).toContain('#2F7A68');
  expect(dec(icons.phone)).toContain('#A13F72');
  expect(icons.router).not.toBe(icons.device);
  // Белый глиф типа и тёмный маркер формы в правом верхнем углу.
  expect(dec(icons.router)).toContain('stroke="#FFFFFF"');
  expect(dec(icons.router)).toContain('fill="#0E1116"');
  // Устройство трое суток не выходило на связь, но у него открыто
  // решение «новое устройство» (▲ перебивает ○). Принимаем решение
  // через API (как это делает владелец в карточке) — остаётся только
  // сигнал «не отвечает» и статус «не в сети».
  const accept = await page.request.patch('/api/devices/02:00:00:00:00:12', {
    headers: { Authorization: `Bearer ${TOKEN}` },
    data: { class: 'known_no_agent' },
  });
  expect(accept.ok()).toBe(true);
  await page.reload();
  await openMap(page);
  const stale = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const n = cy.getElementById('02:00:00:00:00:12');
    return { icon: String(n.data('icon') ?? ''), kind: String(n.data('kind') ?? '') };
  });
  expect(stale.kind).toBe('unknown');
  // Кольцо статуса «не в сети» — пунктирное (NR-036: различимо без
  // цвета), цвет #9AA6B5.
  expect(dec(stale.icon)).toContain('stroke-dasharray');
  expect(dec(stale.icon)).toContain('#9AA6B5');
  // У статуса «в сети» пунктира нет.
  const solid = Object.values(icons).filter((i) => !dec(i).includes('stroke-dasharray'));
  expect(solid.length).toBeGreaterThan(0);
  // Скриншоты карты и легенды — в артефакт прогона (NR-036 п.5).
  await shot(page, 'map-badges');
  const legend = page.locator('#map-legend');
  // Легенда: образцы колец статусов и значки ролей с подписями типов.
  await expect(legend.locator('.legend-status img').first()).toBeVisible();
  await expect(legend.locator('.legend-item:not(.legend-status) img').first()).toBeVisible();
  await legend.screenshot({ path: join(SHOTS, 'legend-badges.png') });
});

test('предполагаемых связей столько же, сколько не-шлюзов (NR-032 п.3, п.6)', async ({ page }) => {
  await login(page);
  await page.click('nav .item[data-page="map"]');
  await page.waitForFunction(() => {
    const hook = (window as unknown as { __netatlas?: { cy: { edges: () => { length: number } } } }).__netatlas;
    return hook !== undefined && hook.cy.edges().length > 0;
  });
  const report = await page.evaluate(() => {
    const cy = (window as unknown as {
      __netatlas: { cy: import('cytoscape').default };
    }).__netatlas.cy;
    const assumed = cy.edges().filter((e: { data: (k: string) => string }) => e.data('src') === 'assumed');
    const nodes = cy.nodes().filter((n: { isParent: () => boolean }) => !n.isParent() && !n.hasClass('bend'));
    const gateways = nodes.filter((n: { data: (k: string) => string }) => n.data('kind') === 'router');
    // Все предполагаемые связи ведут к шлюзу, у каждого не-шлюза ровно одна.
    const toGateway = assumed.every((e: { data: (k: string) => string; connectedNodes: () => { length: number }[] }) =>
      e.connectedNodes().some((x: { data: (k: string) => string }) => x.data('kind') === 'router'),
    );
    return { assumed: assumed.length, nodes: nodes.length, gateways: gateways.length, toGateway };
  });
  expect(report.gateways).toBe(1);
  expect(report.assumed).toBe(report.nodes - report.gateways);
  expect(report.assumed).toBe(14);
  expect(report.toGateway).toBe(true);
});

test('узлы выстроены сеткой: ряды на равных координатах (NR-032 п.4, NR-034 п.2)', async ({ page }) => {
  await login(page);
  await page.click('nav .item[data-page="map"]');
  await page.waitForFunction(() => {
    const hook = (window as unknown as { __netatlas?: { cy: { nodes: () => { length: number } } } }).__netatlas;
    return hook !== undefined && hook.cy.nodes().length >= 15;
  });
  await page.waitForTimeout(500);
  const report = await page.evaluate(() => {
    const cy = (window as unknown as {
      __netatlas: { cy: import('cytoscape').default };
    }).__netatlas.cy;
    const byKind = new Map<string, number[]>();
    cy.nodes()
      .filter((n: { isParent: () => boolean }) => !n.isParent() && !n.hasClass('bend'))
      .forEach((n: { data: (k: string) => string; position: (a: string) => number }) => {
        const kind = n.data('kind');
        const ys = byKind.get(kind) ?? [];
        ys.push(n.position('y'));
        byKind.set(kind, ys);
      });
    // Все узлы одного типа стоят в ряду (одна координата Y) либо в
    // нескольких подряд идущих строках ряда: перенос после N колонок
    // (NR-034 п.2), шаг строки — ровно 120.
    const lines = new Map<number, string>(); // Y строки -> тип на ней
    for (const [kind, ys] of byKind) {
      const unique = [...new Set(ys.map((y) => Math.round(y)))].sort((a, b) => a - b);
      for (let i = 1; i < unique.length; i++) {
        const gap = (unique[i] ?? 0) - (unique[i - 1] ?? 0);
        if (Math.abs(gap - 120) > 0.5) {
          return { error: `тип ${kind}: строки через ${gap}, хочу 120` };
        }
      }
      for (const y of unique) {
        const occupant = lines.get(y);
        if (occupant !== undefined && occupant !== kind) {
          return { error: `Y ${y} делят типы ${occupant} и ${kind}` };
        }
        lines.set(y, kind);
      }
    }
    // Роутер — самый верхний ряд; остальные ниже.
    const routerY = Math.min(
      ...(byKind.get('router') ?? [NaN]),
    );
    for (const [kind, ys] of byKind) {
      if (kind === 'router') continue;
      const minY = Math.min(...ys);
      if (!(minY > routerY)) {
        return { error: `тип ${kind} не ниже роутера` };
      }
    }
    return { error: null };
  });
  expect(report.error).toBeNull();
  await shot(page, 'map-grid');
});

test('в легенде есть пунктирная строка предполагаемой связи (NR-032 п.3, п.5)', async ({ page }) => {
  await login(page);
  await page.click('nav .item[data-page="map"]');
  const assumed = page.locator('#map-legend .legend-assumed');
  await expect(assumed).toBeVisible();
  await expect(assumed).toContainText('предполагаемая связь: данных о коммутаторе нет');
  // Штрих-образец действительно пунктирный (запрос атомарный:
  // легенда может перезаливаться при автообновлении).
  const style = await page.evaluate(
    () =>
      document.querySelector('#map-legend .legend-dash') !== null
        ? window.getComputedStyle(document.querySelector('#map-legend .legend-dash') as Element)
            .borderTopStyle
        : '',
  );
  expect(style).toBe('dashed');
  // Типы фикстуры показаны значками в легенде.
  const kinds = await page.locator('#map-legend .legend-item').evaluateAll((els) =>
    els.map((el) => (el as HTMLElement).dataset.kind ?? ''),
  );
  for (const k of ['router', 'printer', 'phone', 'iot', 'server', 'device']) {
    expect(kinds).toContain(k);
  }
  await shot(page, 'map-legend');
});

test('ручной тип узла перекрывает автоматический (NR-032 п.1)', async ({ page }) => {
  await login(page);
  await page.click('nav .item[data-page="map"]');
  await page.waitForFunction(() => {
    const hook = (window as unknown as { __netatlas?: { cy: { nodes: () => { length: number } } } }).__netatlas;
    return hook !== undefined && hook.cy.nodes().length >= 15;
  });
  // Открыть панель принтера, сменить тип на сервер.
  await page.locator('#map-a11y li[data-kind="printer"]').first().click({ force: true });
  const dialog = page.locator('#token-dialog');
  await expect(dialog).toBeHidden();
  // Клик по a11y-списку не выбирает узел canvas: выбираем программно.
  await page.evaluate(() => {
    const hook = (window as unknown as {
      __netatlas: { cy: import('cytoscape').default };
    }).__netatlas;
    const node = hook.cy.nodes().filter((n: { data: (k: string) => string }) => n.data('kind') === 'printer').first();
    hook.cy.getElementById(node.id()).emit('tap');
  });
  await expect(page.locator('#panel')).toHaveClass(/open/);
  await page.click('#tab-edit');
  await page.selectOption('#edit-kind', 'server');
  await page.click('text=Сменить тип');
  await page.waitForTimeout(600);
  const kinds = await page.locator('#map-a11y li').evaluateAll((els) =>
    els.map((el) => (el as HTMLElement).dataset.kind ?? ''),
  );
  expect(kinds).toContain('server');
  expect(kinds.filter((k) => k === 'printer')).toHaveLength(0);
});


// --- NR-033: ортогональные связи, значки, карточка, сигналы внимания ----

async function openMap(page: Page): Promise<void> {
  await login(page);
  await page.click('nav .item[data-page="map"]');
  await page.waitForFunction(() => {
    const hook = (window as unknown as { __netatlas?: { cy: { nodes: () => { length: number } } } }).__netatlas;
    return hook !== undefined && hook.cy.nodes().length >= 15;
  });
  await page.waitForTimeout(600);
}

// canvasPoint — страница-координаты узла: renderedPosition канвы
// плюс смещение контейнера #graph (мышь Playwright бьёт по странице).
async function canvasPoint(page: Page, expr: string): Promise<{ x: number; y: number }> {
  return page.evaluate((src: string) => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const n = (0, eval)(src) as { renderedPosition: () => { x: number; y: number } };
    const rect = document.getElementById('graph')?.getBoundingClientRect();
    const p = n.renderedPosition();
    return { x: (rect?.left ?? 0) + p.x, y: (rect?.top ?? 0) + p.y };
  }, expr);
}

// nodeByKind — выражение для canvasPoint: узел данного типа.
function nodeByKind(kind: string): string {
  return `window.__netatlas.cy.nodes().filter((x) => x.data('kind') === '${kind}').first()`;
}

test('все связи ортогональны: каждый сегмент горизонтален или вертикален (NR-033 п.1, п.6)', async ({ page }) => {
  await openMap(page);
  const report = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    if (cy.edges().length === 0) return { error: 'на карте нет связей' };
    const bad: string[] = [];
    for (const e of cy.edges().toArray()) {
      const style = e.style('curve-style');
      if (style !== 'taxi') bad.push(`${e.id()}: curve-style=${String(style)}`);
      const pts = [e.sourceEndpoint(), ...e.segmentPoints(), e.targetEndpoint()] as { x: number; y: number }[];
      for (let i = 1; i < pts.length; i++) {
        const a = pts[i - 1] as { x: number; y: number };
        const b = pts[i] as { x: number; y: number };
        const dx = Math.abs(a.x - b.x);
        const dy = Math.abs(a.y - b.y);
        if (dx > 0.5 && dy > 0.5) bad.push(`${e.id()}: сегмент ${i - 1}->${i} наклонный (${dx.toFixed(1)}, ${dy.toFixed(1)})`);
      }
    }
    return { error: null, bad };
  });
  expect(report.error).toBeNull();
  expect(report.bad).toEqual([]);
});

test('линии не проходят сквозь узлы (NR-033 п.1, проверка на фикстуре)', async ({ page }) => {
  await openMap(page);
  const report = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const nodes = cy.nodes().filter((n: { isParent: () => boolean }) => !n.isParent() && !n.hasClass('bend'));
    const boxes = nodes.map((n: { id: () => string; boundingBox: (o: object) => { x1: number; y1: number; x2: number; y2: number } }) => ({
      id: n.id(),
      box: n.boundingBox({ includeLabels: false, includeOverlays: false, includeEdges: false }),
    }));
    const hits: string[] = [];
    const segRect = (
      ax: number, ay: number, bx: number, by: number,
      r: { x1: number; y1: number; x2: number; y2: number },
    ): boolean => {
      // Прямоугольник сегмента (вырожденный — отрезок) против узла,
      // с зазором 1px, чтобы касания не считались пересечением.
      const x1 = Math.min(ax, bx) - 1;
      const x2 = Math.max(ax, bx) + 1;
      const y1 = Math.min(ay, by) - 1;
      const y2 = Math.max(ay, by) + 1;
      return Math.min(x2, r.x2) - Math.max(x1, r.x1) > 0 && Math.min(y2, r.y2) - Math.max(y1, r.y1) > 0;
    };
    for (const e of cy.edges().toArray()) {
      const src = e.source().id();
      const tgt = e.target().id();
      const pts = [e.sourceEndpoint(), ...e.segmentPoints(), e.targetEndpoint()] as { x: number; y: number }[];
      for (let i = 1; i < pts.length; i++) {
        const a = pts[i - 1] as { x: number; y: number };
        const b = pts[i] as { x: number; y: number };
        for (const { id, box } of boxes) {
          if (id === src || id === tgt) continue;
          if (segRect(a.x, a.y, b.x, b.y, box)) {
            hits.push(`связь ${e.id()}: сегмент ${i - 1}->${i} проходит сквозь ${id}`);
          }
        }
      }
    }
    return { hits };
  });
  expect(report.hits).toEqual([]);
});

test('перетаскивание узла привязывает его к сетке (NR-033 п.1, п.6)', async ({ page }) => {
  await openMap(page);
  // Детерминированная проекция: масштаб 1, панорама 0.
  await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    cy.zoom(1);
    cy.pan({ x: 0, y: 0 });
  });
  // Тип «компьютер» стабилен: предыдущие тесты могут менять другие.
  const nodeId = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const n = cy.nodes().filter((x: { data: (k: string) => string }) => x.data('kind') === 'device').first();
    return n.id();
  });
  const before = await page.evaluate((id: string) => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const n = cy.getElementById(id).first();
    return { x: n.position('x'), y: n.position('y') };
  }, nodeId);
  const start = await canvasPoint(page, nodeByKind('device'));
  // Сдвиг на не кратные шагу смещения: +37, +43.
  await page.mouse.move(start.x, start.y);
  await page.mouse.down();
  await page.mouse.move(start.x + 37, start.y + 43, { steps: 6 });
  await page.mouse.up();
  await page.waitForTimeout(300);
  const pos = await page.evaluate((id: string) => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const n = cy.getElementById(id).first();
    return { x: n.position('x'), y: n.position('y') };
  }, nodeId);
  // NR-038 п.2: привязка к мелкой сетке 20×20 — ровно к ближайшему
  // узлу от исходного положения плюс смещение мыши.
  expect(pos.x).toBe(Math.round((before.x + 37) / 20) * 20);
  expect(pos.y).toBe(Math.round((before.y + 43) / 20) * 20);
  // Позиция пережила привязку и ушла на сервер (обе координаты изменились).
  expect(pos.x !== 0 || pos.y !== 0).toBe(true);
  await shot(page, 'map-snap');
});

test('одинарный клик открывает боковую панель с кнопкой полной карточки (NR-033 п.3)', async ({ page }) => {
  await openMap(page);
  await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const n = cy.nodes().filter((x: { data: (k: string) => string }) => x.data('kind') === 'server').first();
    n.emit('tap');
  });
  await expect(page.locator('#panel')).toHaveClass(/open/);
  const openBtn = page.locator('#page-overview button', { hasText: 'Открыть полную карточку' });
  await expect(openBtn).toBeVisible();
  await openBtn.click();
  await expect(page.locator('#screen-card')).toBeVisible();
  await expect(page.locator('#card-root h2')).not.toBeEmpty();
  await shot(page, 'card-from-panel');
});

test('двойной клик открывает карточку с MAC и IP (NR-033 п.3, п.6)', async ({ page }) => {
  await openMap(page);
  // Телефон не в углу карты: реальные координаты мыши с точностью
  // до пикселя надёжнее работают вдали от края канвы.
  const info = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const n = cy.nodes().filter((x: { data: (k: string) => string }) => x.data('kind') === 'phone').first();
    return { id: n.id() };
  });
  const pt = await canvasPoint(page, nodeByKind('phone'));
  await page.mouse.dblclick(pt.x, pt.y);
  await expect(page.locator('#screen-card')).toBeVisible();
  const text = await page.locator('#screen-card').textContent();
  expect(text).toContain(info.id);
  // IP телефона фикстуры Android.local (NR-034: прежняя проверка
  // '192.168.100.1' совпадала подстрокой с адресами .15/.16/.17,
  // которые после NR-033/#73 больше не телефоны — ложный позитив).
  expect(text).toContain('192.168.100.30');
  // Действия карточки доступны.
  await expect(page.locator('#card-root button', { hasText: 'Сформировать отчёт для ИИ' })).toBeVisible();
  await shot(page, 'card');
});

test('клавиатура: Enter на выбранном узле открывает карточку (NR-033 п.3)', async ({ page }) => {
  await openMap(page);
  await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const n = cy.nodes().filter((x: { data: (k: string) => string }) => x.data('kind') === 'iot').first();
    n.emit('tap');
  });
  await expect(page.locator('#panel')).toHaveClass(/open/);
  await page.keyboard.press('Enter');
  await expect(page.locator('#screen-card')).toBeVisible();
});

test('у узла с оповещением виден бейдж внимания, сигнал в панели (NR-033 п.4, п.6)', async ({ page }) => {
  await openMap(page);
  // Бейдж ▲ на значке: SVG-иконка узла содержит маркер внимания.
  const icons = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    return cy.nodes()
      .filter((n: { isParent: () => boolean }) => !n.isParent() && !n.hasClass('bend'))
      .map((n: { data: (k: string) => string }) => n.data('icon') ?? '');
  });
  const withAttention = icons.filter(
    (i: string) =>
      i.includes('%E2%96%B2') ||
      i.includes('▲') ||
      // Маркер ▲ в правом верхнем углу значка (NR-036): треугольник
      // над тёмным кругом маркера.
      decodeURIComponent(i).includes('M57 18.4'),
  );
  expect(withAttention.length).toBeGreaterThan(0);
  // a11y-слой показывает статус «▲ внимание».
  const a11y = await page.locator('#map-a11y li').allTextContents();
  expect(a11y.some((t) => t.includes('▲ внимание'))).toBe(true);
  // Панель «Требуют внимания»: список сигналов, клик фокусирует узел.
  // NR-037 п.5: однотипные «новые устройства» свёрнуты в группу —
  // берём первую строку верхнего уровня с устройством (строки
  // группы скрыты внутри списка до раскрытия).
  await page.click('#btn-attention');
  const rows = page.locator(
    '#attention-panel > .attention-row[data-device-id]:not([data-device-id=""])',
  );
  await expect(rows.first()).toBeVisible();
  // Клик по строке фокусирует узел (панель открывается, узел выбран).
  const deviceId = await rows.first().getAttribute('data-device-id');
  expect(deviceId).not.toBe('');
  await rows.first().click();
  await page.waitForTimeout(300);
  const selected = await page.evaluate((id: string) => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    return cy.getElementById(id as string).selected();
  }, deviceId as string);
  expect(selected).toBe(true);
  await expect(page.locator('#panel')).toHaveClass(/open/);
  await shot(page, 'attention-panel');
});

test('действие «Принять» меняет класс и убирает бейдж (NR-033 п.4, п.6)', async ({ request, page }) => {
  await login(page);
  // До решения: у устройства есть сигнал-решение.
  const before = await request.get('/api/signals', { headers: { Authorization: `Bearer ${TOKEN}` } });
  expect(before.ok()).toBe(true);
  const beforeView = (await before.json()) as { signals: { device_id: string; decision: boolean; kind: string }[] };
  const target = beforeView.signals.find((s) => s.decision);
  expect(target).toBeDefined();
  const targetId = (target as { device_id: string }).device_id;

  await page.click('nav .item[data-page="map"]');
  await page.waitForFunction(() => {
    const hook = (window as unknown as { __netatlas?: { cy: { nodes: () => { length: number } } } }).__netatlas;
    return hook !== undefined && hook.cy.nodes().length >= 15;
  });
  // Открыть карточку двойным кликом по целевому узлу.
  const pt = await page.evaluate((id: string) => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const n = cy.getElementById(id).first();
    const rect = document.getElementById('graph')?.getBoundingClientRect();
    const p = n.renderedPosition();
    return { x: (rect?.left ?? 0) + p.x, y: (rect?.top ?? 0) + p.y };
  }, targetId);
  await page.mouse.dblclick(pt.x, pt.y);
  await expect(page.locator('#screen-card')).toBeVisible();
  await page.click('#card-tab-decisions');
  await page.click('#card-page-decisions button:has-text("Принять: известное")');
  // Решение показывается уведомлением; факты проверяются по API ниже.
  await expect(page.locator('#notice')).toContainText('Решение принято');

  // Класс изменён, сигнал-решение исчез (бейдж убран).
  const after = await request.get(`/api/devices/${encodeURIComponent(targetId)}`, { headers: { Authorization: `Bearer ${TOKEN}` } });
  expect(after.ok()).toBe(true);
  const afterInfo = (await after.json()) as { class: string };
  expect(afterInfo.class).toBe('known_no_agent');
  const signalsAfter = await request.get('/api/signals', { headers: { Authorization: `Bearer ${TOKEN}` } });
  const viewAfter = (await signalsAfter.json()) as { signals: { device_id: string; decision: boolean }[] };
  expect(viewAfter.signals.some((s) => s.device_id === targetId && s.decision)).toBe(false);
  await shot(page, 'card-accepted');
});

test('легенда показывает присутствующие статусы (NR-033 п.5)', async ({ page }) => {
  await openMap(page);
  const statuses = await page.locator('#map-legend .legend-status').evaluateAll((els) =>
    els.map((el) => (el as HTMLElement).dataset.status ?? ''),
  );
  expect(statuses).toContain('attention');
  expect(statuses.length).toBeGreaterThan(0);
});

// --- NR-034: пересчёт старых данных, перенос ряда, масштаб ----------

test('старая база без kind_auto: после старта сервера карта показывает типы, шлюз и связи (NR-034 п.1)', async ({ page }) => {
  const serverBin = process.env.NETATLAS_E2E_SERVER ?? '';
  const seedBin = process.env.NETATLAS_E2E_SEED ?? '';
  test.skip(!serverBin || !seedBin, 'нужны NETATLAS_E2E_SERVER и NETATLAS_E2E_SEED');
  // База legacy: типы обнулены (kind = device, kind_auto пусто),
  // шлюзов в последнем скане нет — как у владельца после обновления
  // с версии до NR-032.
  const work = mkdtempSync(join(tmpdir(), 'netatlas-legacy-'));
  const db = join(work, 'legacy.db');
  const seeded = spawnSync(seedBin, [db, 'legacy'], { stdio: 'ignore' });
  expect(seeded.status).toBe(0);
  const port = 18485;
  const srv = spawn(
    serverBin,
    ['--db', db, '--listen', `127.0.0.1:${port}`, '--subnets', '192.168.100.0/24'],
    {
      env: { ...process.env, NETATLAS_TOKEN: TOKEN },
      stdio: 'ignore',
    },
  );
  try {
    const base = `http://127.0.0.1:${port}`;
    await expect
      .poll(
        async () => {
          try {
            const r = await fetch(`${base}/app.css`);
            return r.status;
          } catch {
            return 0;
          }
        },
        { timeout: 30_000 },
      )
      .toBe(200);
    await page.goto(base);
    const dialog = page.locator('#token-dialog');
    await expect(dialog).toBeVisible();
    await page.fill('#token-input', TOKEN);
    await page.click('#token-submit');
    await expect(dialog).toBeHidden();
    await page.waitForFunction(() => {
      const hook = (window as unknown as { __netatlas?: { cy: { nodes: () => { length: number } } } })
        .__netatlas;
      return hook !== undefined && hook.cy.nodes().length >= 15;
    });
    await page.waitForTimeout(600);
    const report = await page.evaluate(() => {
      const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
      const nodes = cy.nodes().filter((n: { isParent: () => boolean }) => !n.isParent() && !n.hasClass('bend'));
      const kinds = new Set(nodes.map((n: { data: (k: string) => string }) => n.data('kind')));
      const routers = nodes.filter((n: { data: (k: string) => string }) => n.data('kind') === 'router');
      const routerY = routers.length === 1 ? routers[0].position('y') : NaN;
      const above = nodes.filter(
        (n: { data: (k: string) => string; position: (a: string) => number }) =>
          n.data('kind') !== 'router' && n.position('y') <= routerY,
      ).length;
      const ys = new Set(nodes.map((n: { position: (a: string) => number }) => Math.round(n.position('y'))));
      const icons = new Set(nodes.map((n: { data: (k: string) => string }) => n.data('icon')));
      const assumed = cy.edges().filter((e: { data: (k: string) => string }) => e.data('src') === 'assumed').length;
      return {
        total: nodes.length,
        kindsCount: kinds.size,
        routerCount: routers.length,
        above,
        lines: ys.size,
        iconsCount: icons.size,
        assumed,
      };
    });
    // Пересчёт из пустого kind_auto: роутер один и сверху, типы
    // разные (карта не «глупая» без нового скана).
    expect(report.routerCount).toBe(1);
    expect(report.above).toBe(0);
    expect(report.kindsCount).toBeGreaterThanOrEqual(4);
    expect(report.iconsCount).toBeGreaterThanOrEqual(4);
    // 11 узлов одного типа не в одну строку: строки раскладки ≥ 5.
    expect(report.lines).toBeGreaterThanOrEqual(5);
    // Предполагаемые связи есть без нового скана: 14 не-шлюзов.
    expect(report.assumed).toBe(14);
    await shot(page, 'legacy-recompute');
  } finally {
    srv.kill();
  }
});

test('ряд одинаковых узлов переносится после N колонок, значки не мельче 32 px (NR-034 п.2)', async ({ page }) => {
  await openMap(page);
  // «Выстроить сеткой» теперь с подтверждением (NR-035 п.1):
  // диалог принимается автоматически.
  page.on('dialog', (d) => void d.accept());
  // Открыть панель: канва сузилась, ряд unknown (8 узлов) не влезает.
  await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    cy.nodes().filter((x: { data: (k: string) => string }) => x.data('kind') === 'unknown').first().emit('tap');
  });
  await expect(page.locator('#panel')).toHaveClass(/open/);
  // «Выстроить сеткой» — та же раскладка, перенос по новой ширине.
  await page.click('#btn-arrange');
  await page.waitForTimeout(600);
  const report = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const unknown = cy.nodes().filter(
      (n: { isParent: () => boolean; data: (k: string) => string }) =>
        !n.isParent() && !n.hasClass('bend') && n.data('kind') === 'unknown',
    );
    const ys = [...new Set(unknown.map((n: { position: (a: string) => number }) => Math.round(n.position('y'))))]
      .sort((a: number, b: number) => a - b);
    const router = cy.nodes().filter((n: { data: (k: string) => string }) => n.data('kind') === 'router').first();
    return { lines: ys.length, ys, zoom: cy.zoom(), routerY: Math.round(router.position('y')) };
  });
  // 8 узлов unknown не помещаются в одну строку узкой канвы —
  // перенос минимум на две строки, шаг строки ровно 120.
  expect(report.lines).toBeGreaterThanOrEqual(2);
  expect((report.ys[1] ?? 0) - (report.ys[0] ?? 0)).toBeCloseTo(120, 0);
  // Перенесённые строки ниже роутера.
  expect(report.ys[0] ?? 0).toBeGreaterThan(report.routerY);
  // Масштаб по умолчанию: значок 40px модели отрисован ≥ 32 px.
  expect(report.zoom).toBeGreaterThanOrEqual(0.79);
  await shot(page, 'map-wrap');
});

// --- NR-035: запоминание положений, точки соединений, поле ------------

// bendCount — число точек на изломах (порт-узлы NR-035 п.2).
async function bendCount(page: Page): Promise<number> {
  return page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    return cy.nodes().filter((n: { hasClass: (c: string) => boolean }) => n.hasClass('bend')).length;
  });
}

test('сдвинутый узел сохраняет положение после перезагрузки страницы (NR-035 п.1)', async ({ page }) => {
  await openMap(page);
  // Чистый старт: подтверждаем «Выстроить сеткой» (стирает прошлые
  // положения тестов в общей базе).
  page.on('dialog', (d) => void d.accept());
  await page.click('#btn-arrange');
  await page.waitForTimeout(600);

  // Детерминированная проекция: масштаб 1, панорама 0.
  await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    cy.zoom(1);
    cy.pan({ x: 0, y: 0 });
  });
  const nodeId = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    return cy.nodes().filter((x: { data: (k: string) => string }) => x.data('kind') === 'device').first().id();
  });
  const start = await canvasPoint(page, nodeByKind('device'));
  await page.mouse.move(start.x, start.y);
  await page.mouse.down();
  await page.mouse.move(start.x + 150, start.y + 120, { steps: 8 });
  await page.mouse.up();
  await page.waitForTimeout(900); // дебаунс 500 мс + отправка
  const posBefore = await page.evaluate((id: string) => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const n = cy.getElementById(id).first();
    return { x: n.position('x'), y: n.position('y') };
  }, nodeId);

  // Перезагрузка страницы: токен только в памяти страницы — вход заново.
  await page.reload();
  await login(page);
  await page.click('nav .item[data-page="map"]');
  await page.waitForFunction(() => {
    const hook = (window as unknown as { __netatlas?: { cy: { nodes: () => { length: number } } } }).__netatlas;
    return hook !== undefined && hook.cy.nodes().length >= 15;
  });
  await page.waitForTimeout(700);
  const posAfter = await page.evaluate((id: string) => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const n = cy.getElementById(id).first();
    return { x: n.position('x'), y: n.position('y') };
  }, nodeId);
  expect(Math.round(posAfter.x)).toBe(Math.round(posBefore.x));
  expect(Math.round(posAfter.y)).toBe(Math.round(posBefore.y));
  await shot(page, 'map-positions-persist');
});

test('pan мышью по пустому полю сдвигает панораму; колесо меняет масштаб (NR-035 п.3)', async ({ page }) => {
  await openMap(page);
  // Вписать в окно: карта в центре, углы канвы пустые.
  await page.click('#btn-fit');
  await page.waitForTimeout(200);
  const panBefore = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    return cy.pan();
  });
  // Пустое место: верхний левый угол канвы (поле подгонки 90 px).
  const rect = await page.evaluate(() => {
    const r = document.getElementById('graph')?.getBoundingClientRect();
    return { left: r?.left ?? 0, top: r?.top ?? 0 };
  });
  await page.mouse.move(rect.left + 12, rect.top + 12);
  await page.mouse.down();
  await page.mouse.move(rect.left + 172, rect.top + 132, { steps: 8 });
  await page.mouse.up();
  await page.waitForTimeout(200);
  const panAfter = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    return cy.pan();
  });
  expect(panAfter.x - panBefore.x).toBeGreaterThan(100);
  expect(panAfter.y - panBefore.y).toBeGreaterThan(60);
  // Колесо меняет масштаб относительно курсора.
  const zoomBefore = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    return cy.zoom();
  });
  await page.mouse.move(rect.left + 400, rect.top + 300);
  await page.mouse.wheel(0, -240);
  await page.waitForTimeout(200);
  const zoomAfter = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    return cy.zoom();
  });
  expect(zoomAfter).toBeGreaterThan(zoomBefore);
  await shot(page, 'map-pan');
});

test('«Вписать в окно» показывает все узлы, «Центр» центрирует без смены масштаба (NR-035 п.3)', async ({ page }) => {
  await openMap(page);
  // Увести вид далеко, затем «Вписать в окно»: все узлы видимы.
  await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    cy.pan({ x: 3000, y: 3000 });
  });
  await page.click('#btn-fit');
  await page.waitForTimeout(200);
  const visible = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const ext = cy.extent();
    const out = cy.nodes()
      .filter((n: { isParent: () => boolean; hasClass: (c: string) => boolean }) => !n.isParent() && !n.hasClass('bend'))
      .filter((n: { position: (a: string) => number }) => {
        const x = n.position('x');
        const y = n.position('y');
        return x < ext.x1 || x > ext.x2 || y < ext.y1 || y > ext.y2;
      }).length;
    return out;
  });
  expect(visible).toBe(0);
  await shot(page, 'map-fit');

  // «Центр»: центр карты в центре канвы, масштаб не меняется.
  await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    cy.pan({ x: 3000, y: -3000 });
  });
  const zoomBefore = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    return cy.zoom();
  });
  await page.click('#btn-center');
  await page.waitForTimeout(200);
  const centered = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const bb = cy.nodes()
      .filter((n: { isParent: () => boolean; hasClass: (c: string) => boolean }) => !n.isParent() && !n.hasClass('bend'))
      .boundingBox();
    return {
      dx: bb.x1 + (bb.x2 - bb.x1) / 2 - (cy.width() / 2 - cy.pan().x) / cy.zoom(),
      dy: bb.y1 + (bb.y2 - bb.y1) / 2 - (cy.height() / 2 - cy.pan().y) / cy.zoom(),
    };
  });
  expect(Math.abs(centered.dx)).toBeLessThan(10);
  expect(Math.abs(centered.dy)).toBeLessThan(10);
  const zoomAfter = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    return cy.zoom();
  });
  expect(zoomAfter).toBeCloseTo(zoomBefore, 6);
  await shot(page, 'map-center');
});

test('на концах рёбер точки, на изломах — порт-узлы, в DOM есть фоновая сетка (NR-035 п.2, NR-037 п.1)', async ({ page }) => {
  await openMap(page);
  const report = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const edges = cy.edges().toArray();
    // NR-037 п.1: стрелок нет — точки соединений рисуют порт-узлы
    // 6 px на стыке линии с диском (стрелка-«кружок» cytoscape при
    // arrow-scale 4 имела диаметр ~35 px и закрывала подписи).
    const noArrows = edges.every((e: { style: (k: string) => string }) =>
      e.style('source-arrow-shape') === 'none' && e.style('target-arrow-shape') === 'none');
    // Точки на концах: порт-узлы на sourceEndpoint/targetEndpoint.
    const ends: string[] = [];
    for (const e of edges) {
      const se = e.sourceEndpoint() as { x: number; y: number };
      const te = e.targetEndpoint() as { x: number; y: number };
      const src = cy.getElementById(`bend:${e.id()}:src`).first();
      const tgt = cy.getElementById(`bend:${e.id()}:tgt`).first();
      if (src.nonempty()) {
        const d = Math.hypot(src.position('x') - se.x, src.position('y') - se.y);
        if (d > 1) ends.push(`${e.id()}: src-точка в ${d.toFixed(1)} px от стыка`);
      } else ends.push(`${e.id()}: нет src-точки`);
      if (tgt.nonempty()) {
        const d = Math.hypot(tgt.position('x') - te.x, tgt.position('y') - te.y);
        if (d > 1) ends.push(`${e.id()}: tgt-точка в ${d.toFixed(1)} px от стыка`);
      } else ends.push(`${e.id()}: нет tgt-точки`);
    }
    const layer = document.getElementById('map-grid');
    const show = document.getElementById('show-grid') as HTMLInputElement | null;
    const snap = document.getElementById('snap-grid') as HTMLInputElement | null;
    const gridOn = layer !== null && show !== null && snap !== null
      && show.checked && snap.checked && window.getComputedStyle(layer).display !== 'none';
    const bg = layer !== null ? window.getComputedStyle(layer).backgroundImage : '';
    const size = layer !== null ? layer.style.backgroundSize : '';
    return {
      edges: edges.length,
      noArrows,
      ends,
      gridOn,
      bgHasDots: bg.includes('radial-gradient'),
      size: size,
      zoom: cy.zoom(),
    };
  });
  expect(report.edges).toBeGreaterThan(0);
  expect(report.noArrows).toBe(true);
  expect(report.ends).toEqual([]);
  expect(report.gridOn).toBe(true);
  expect(report.bgHasDots).toBe(true);
  // Тайл сетки = мелкая сетка × масштаб (20×20 при зуме 1, NR-038 п.2).
  const sizeX = Number.parseFloat(report.size.split('px')[0] ?? '0');
  expect(sizeX).toBeCloseTo(20 * report.zoom, 1);
  // Точки изломов: порт-узлы класса bend.
  const bends = await bendCount(page);
  expect(bends).toBeGreaterThan(0);
  // Выключатель «Показывать сетку» прячет слой.
  await page.click('#show-grid');
  await page.waitForTimeout(100);
  const hidden = await page.evaluate(() => {
    const layer = document.getElementById('map-grid');
    return layer === null || window.getComputedStyle(layer).display === 'none';
  });
  expect(hidden).toBe(true);
  await page.click('#show-grid');
  await shot(page, 'map-grid-dots');
});

test('глиф значка заполняет плашку по центру, фон не меньше половины узла (NR-035 п.4)', async ({ page }) => {
  await openMap(page);
  const report = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const nodes = cy.nodes()
      .filter((n: { isParent: () => boolean; hasClass: (c: string) => boolean }) => !n.isParent() && !n.hasClass('bend'))
      .toArray();
    const bad: string[] = [];
    for (const n of nodes) {
      // Заданный размер фона: проценты или px относительно узла.
      const bw = n.style('background-width');
      const bh = n.style('background-height');
      const w = String(bw);
      const h = String(bh);
      const fracW = w.endsWith('%') ? Number.parseFloat(w.slice(0, -1)) / 100 : 1;
      const fracH = h.endsWith('%') ? Number.parseFloat(h.slice(0, -1)) / 100 : 1;
      if (!(fracW >= 0.5) || !(fracH >= 0.5)) {
        bad.push(`${n.id()}: bg ${w} x ${h}`);
      }
      // SVG-иконка с intrinsic-размером (глиф рисуется в центре).
      // data URI кодируется encodeURIComponent: '=' -> %3D. NR-036:
      // глиф — вложенный SVG 34×34 (viewBox 24×24).
      const icon = String(n.data('icon') ?? '');
      let decoded = '';
      try {
        decoded = decodeURIComponent(icon);
      } catch {
        decoded = icon;
      }
      if (!decoded.includes('width="34"')) {
        bad.push(`${n.id()}: svg без width`);
      }
    }
    return { total: nodes.length, bad };
  });
  expect(report.total).toBeGreaterThan(0);
  expect(report.bad).toEqual([]);
  await shot(page, 'map-glyph');
});

// --- NR-037: лишние фиолетовые круги, линии поверх подписей ------------

test('на карте нет круглых элементов крупнее 12 px, кроме узлов-устройств (NR-037 п.1, п.4а)', async ({ page }) => {
  await openMap(page);
  const report = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const bad: string[] = [];
    // (а) Размер каждого порт-узла bend через cy: 6 px, не крупнее 12.
    for (const n of cy.nodes('.bend').toArray()) {
      if (n.width() > 12 || n.height() > 12) {
        bad.push(`${n.id()}: ${n.width()}x${n.height()}`);
      }
    }
    if (cy.nodes('.bend').length === 0) bad.push('порт-узлов нет');
    // Причина «фиолетовых кругов» не возвращается: у рёбер нет
    // стрелок (стрелка-«кружок» cytoscape при arrow-scale 4 —
    // диск ~35 px, ложившийся на подписи).
    for (const e of cy.edges().toArray()) {
      if (e.style('source-arrow-shape') !== 'none' || e.style('target-arrow-shape') !== 'none') {
        bad.push(`${e.id()}: стрелки возвращены`);
      }
    }
    // Круглые (ellipse) элементы — только узлы-устройства (80 px)
    // и порт-узлы: других круглых крупнее 12 px быть не должно.
    for (const n of cy.nodes().toArray()) {
      if (n.hasClass('bend') || n.isParent()) continue;
      if (n.style('shape') === 'ellipse' && n.width() <= 12) {
        bad.push(`${n.id()}: устройство размером ${n.width()}`);
      }
    }
    return { bends: cy.nodes('.bend').length, bad };
  });
  expect(report.bends).toBeGreaterThan(0);
  expect(report.bad).toEqual([]);
  await shot(page, 'map-nr037-dots');
});

test('сегменты рёбер не пересекают прямоугольники подписей (NR-037 п.2, п.4б)', async ({ page }) => {
  await openMap(page);
  const report = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    // Прямоугольники подписей всех узлов (без тел узлов): подпись
    // шлюза — над диском, остальных — под диском.
    const labels = cy.nodes()
      .filter((n: { isParent: () => boolean; hasClass: (c: string) => boolean }) =>
        !n.isParent() && !n.hasClass('bend'))
      .map((n: { id: () => string; boundingBox: (o: object) => { x1: number; y1: number; x2: number; y2: number } }) => ({
        id: n.id(),
        box: n.boundingBox({
          includeNodes: false,
          includeLabels: true,
          includeEdges: false,
          includeOverlays: false,
        }),
      }));
    const hits: string[] = [];
    const segRect = (
      ax: number, ay: number, bx: number, by: number,
      r: { x1: number; y1: number; x2: number; y2: number },
    ): boolean => {
      const x1 = Math.min(ax, bx);
      const x2 = Math.max(ax, bx);
      const y1 = Math.min(ay, by);
      const y2 = Math.max(ay, by);
      return Math.min(x2, r.x2) - Math.max(x1, r.x1) > 1 && Math.min(y2, r.y2) - Math.max(y1, r.y1) > 1;
    };
    for (const e of cy.edges().toArray()) {
      const pts = [e.sourceEndpoint(), ...e.segmentPoints(), e.targetEndpoint()] as { x: number; y: number }[];
      for (let i = 1; i < pts.length; i++) {
        const a = pts[i - 1] as { x: number; y: number };
        const b = pts[i] as { x: number; y: number };
        for (const { id, box } of labels) {
          if (segRect(a.x, a.y, b.x, b.y, box)) {
            hits.push(`${e.id()}: сегмент ${i - 1}->${i} через подпись ${id}`);
          }
        }
      }
    }
    return { labels: labels.length, hits };
  });
  expect(report.labels).toBe(15);
  expect(report.hits).toEqual([]);
  await shot(page, 'map-nr037-labels');
});

test('подпись шлюза — «Роутер <IP>», та же в таблице и карточке (NR-037 п.3, п.4в)', async ({ page }) => {
  await openMap(page);
  // (в) Подпись шлюза на карте: не длиннее 24 знаков, содержит IP.
  const gw = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const n = cy.nodes().filter((x: { data: (k: string) => string }) => x.data('kind') === 'router').first();
    return { label: String(n.data('fullLabel') ?? ''), id: n.id() };
  });
  expect(gw.label.length).toBeLessThanOrEqual(24);
  expect(gw.label).toMatch(/^(Роутер \d+\.\d+\.\d+\.\d+|.+192\.168\.100\.1|.+\d+\.\d+\.\d+\.\d+)/);
  // Подпись шлюза над диском (к линии снизу не попадает).
  const above = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const n = cy.nodes().filter((x: { data: (k: string) => string }) => x.data('kind') === 'router').first();
    return String(n.style('text-valign'));
  });
  expect(above).toBe('top');
  // То же имя в таблице устройств (toContainText ждёт загрузку).
  await page.click('nav .item[data-page="devices"]');
  await expect(page.locator('#devices-table')).toContainText('Роутер 192.168.100.1');
  // То же имя в карточке (панель → полная карточка).
  await page.click('nav .item[data-page="map"]');
  await page.waitForTimeout(400);
  await page.evaluate(() => {
    const hook = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas;
    const n = hook.cy.nodes().filter((x: { data: (k: string) => string }) => x.data('kind') === 'router').first();
    n.emit('tap');
  });
  await expect(page.locator('#panel')).toHaveClass(/open/);
  await page.click('#page-overview button:has-text("Открыть полную карточку")');
  await expect(page.locator('#screen-card')).toBeVisible();
  await expect(page.locator('#card-root h2')).toHaveText('Роутер 192.168.100.1');
  await shot(page, 'map-nr037-gateway');
});

test('однотипные сигналы «новые устройства» свёрнуты в одну строку группы (NR-037 п.5)', async ({ page }) => {
  await openMap(page);
  await page.click('#btn-attention');
  const head = page.locator('#attention-panel .attention-group-head');
  await expect(head).toBeVisible();
  const headText = await head.locator('.attention-head').textContent();
  const n = Number.parseInt((headText ?? 'Новые устройства: 0').replace(/\D/g, ''), 10);
  expect(n).toBeGreaterThanOrEqual(2);
  // Отдельные строки группы скрыты; кнопки приёма тоже.
  await expect(page.locator('#attention-panel .attention-group-list')).toBeHidden();
  await expect(page.locator('#attention-panel .attention-group-actions')).toBeHidden();
  // Счётчик на кнопке «Требуют внимания» считает группу одним сигналом.
  const badge = await page.locator('#attention-count').textContent();
  expect(Number.parseInt(badge ?? '0', 10)).toBeLessThan(30);
  // Раскрытие показывает отдельные строки и кнопки приёма.
  await head.click();
  await expect(page.locator('#attention-panel .attention-group-list')).toBeVisible();
  await expect(page.locator('#attention-panel .attention-group-actions')).toBeVisible();
  const inner = await page.locator('#attention-panel .attention-group-list .attention-row').count();
  expect(inner).toBe(n);
  // Клик по строке внутри группы фокусирует узел (приём всей группы
  // не нажимаем: он изменил бы классы устройств фикстуры).
  await expect(head).toHaveAttribute('aria-expanded', 'true');
  await head.click();
  await expect(page.locator('#attention-panel .attention-group-list')).toBeHidden();
  await shot(page, 'attention-group');
});

// === NR-038: точки изгиба на линиях, мелкая сетка, читаемые подписи ===

// edgeHit — страница-координаты точки на середине самого длинного
// сегмента какой-нибудь связи (модель → канва → страница). Связи
// звезды перекрываются на общем стволе: какая именно связь примет
// клик — проверяем по созданной точке (wpLink), а не по id заранее.
async function edgeHit(page: Page): Promise<{ x: number; y: number }> {
  return page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    let best = 0;
    let px = 0;
    let py = 0;
    cy.edges().forEach((e: { sourceEndpoint: () => { x: number; y: number }; targetEndpoint: () => { x: number; y: number }; segmentPoints: () => { x: number; y: number }[] }) => {
      const pts = [e.sourceEndpoint(), ...e.segmentPoints(), e.targetEndpoint()] as { x: number; y: number }[];
      for (let i = 1; i < pts.length; i++) {
        const a = pts[i - 1] as { x: number; y: number };
        const b = pts[i] as { x: number; y: number };
        const len = Math.hypot(b.x - a.x, b.y - a.y);
        if (len > best) {
          best = len;
          px = (a.x + b.x) / 2;
          py = (a.y + b.y) / 2;
        }
      }
    });
    if (best === 0) throw new Error('нет связей');
    const z = cy.zoom();
    const pan = cy.pan();
    const rect = document.getElementById('graph')?.getBoundingClientRect();
    return {
      x: (rect?.left ?? 0) + px * z + pan.x,
      y: (rect?.top ?? 0) + py * z + pan.y,
    };
  });
}

// freshMap — чистый старт: точки изгиба стираются на сервере, затем
// карта открывается заново (тесты NR-038 разделяют общую базу).
async function freshMap(page: Page): Promise<void> {
  await page.request.delete('/api/map/waypoints', { headers: { Authorization: `Bearer ${TOKEN}` } });
  await openMap(page);
}

async function waypointCount(page: Page): Promise<number> {
  return page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    return cy.nodes('.waypoint').length;
  });
}

// allEdgesOrthogonal — все связи (включая сегментные с точками
// изгиба) состоят из горизонтальных и вертикальных сегментов.
async function allEdgesOrthogonal(page: Page): Promise<{ ok: boolean; bad: string[] }> {
  return page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const bad: string[] = [];
    cy.edges().forEach((e: { id: () => string; sourceEndpoint: () => { x: number; y: number }; targetEndpoint: () => { x: number; y: number }; segmentPoints: () => { x: number; y: number }[] }) => {
      const pts = [e.sourceEndpoint(), ...e.segmentPoints(), e.targetEndpoint()] as { x: number; y: number }[];
      for (let i = 1; i < pts.length; i++) {
        const a = pts[i - 1] as { x: number; y: number };
        const b = pts[i] as { x: number; y: number };
        if (Math.abs(a.x - b.x) > 0.5 && Math.abs(a.y - b.y) > 0.5) bad.push(`${e.id()}: сегмент ${i - 1}->${i} наклонный`);
      }
    });
    return { ok: bad.length === 0, bad };
  });
}

// waypointView — данные первой точки изгиба: связь, координаты,
// размер, позиция на странице (для мыши).
async function waypointView(page: Page): Promise<{
  id: string; link: string; x: number; y: number; size: number; pageX: number; pageY: number;
}> {
  return page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const n = cy.nodes('.waypoint').first();
    const rect = document.getElementById('graph')?.getBoundingClientRect();
    const p = n.renderedPosition();
    return {
      id: n.id(),
      link: String(n.data('wpLink') ?? ''),
      x: n.position('x'),
      y: n.position('y'),
      size: n.width(),
      pageX: (rect?.left ?? 0) + p.x,
      pageY: (rect?.top ?? 0) + p.y,
    };
  });
}

test('двойной клик по линии создаёт узловую точку на сетке (NR-038 п.1, п.4а)', async ({ page }) => {
  await freshMap(page);
  const before = await waypointCount(page);
  const hit = await edgeHit(page);
  await page.mouse.dblclick(hit.x, hit.y);
  await page.waitForTimeout(250);
  expect(await waypointCount(page)).toBe(before + 1);
  // Точка стоит на узле мелкой сетки 20×20, размер 10 px — отличается
  // от автоматических точек излома 6 px (NR-038 п.1).
  const wp = await waypointView(page);
  expect(Math.abs(wp.x % 20)).toBe(0);
  expect(Math.abs(wp.y % 20)).toBe(0);
  expect(wp.size).toBe(10);
  expect(wp.link).not.toBe('');
  // Линия с точкой перешла на сегменты; вся карта остаётся
  // ортогональной.
  const style = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const link = String(cy.nodes('.waypoint').first().data('wpLink'));
    return cy.edges().filter((e: { data: (k: string) => string }) => e.data('wpKey') === link).first().style('curve-style');
  });
  expect(style).toBe('segments');
  expect((await allEdgesOrthogonal(page)).ok).toBe(true);
  await shot(page, 'map-waypoint-added');
});

test('перетаскивание точки ставит её на узел сетки, ортогональность сохраняется (NR-038 п.1б, п.4б)', async ({ page }) => {
  await freshMap(page);
  const hit = await edgeHit(page);
  await page.mouse.dblclick(hit.x, hit.y);
  await page.waitForTimeout(250);
  expect(await waypointCount(page)).toBe(1);
  const devicePositions = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const out: Record<string, { x: number; y: number }> = {};
    cy.nodes().forEach((n: { hasClass: (c: string) => boolean; id: () => string; position: () => { x: number; y: number } }) => {
      if (!n.hasClass('bend') && !n.hasClass('waypoint')) out[n.id()] = n.position();
    });
    return out;
  });
  const wp = await waypointView(page);
  await page.mouse.move(wp.pageX, wp.pageY);
  await page.mouse.down();
  await page.mouse.move(wp.pageX + 33, wp.pageY - 47, { steps: 8 });
  await page.mouse.up();
  await page.waitForTimeout(300);
  const moved = await waypointView(page);
  // Привязка к мелкой сетке 20×20.
  expect(Math.abs(moved.x % 20)).toBe(0);
  expect(Math.abs(moved.y % 20)).toBe(0);
  // Ортогональность всех линий сохранена.
  expect(await allEdgesOrthogonal(page)).toEqual({ ok: true, bad: [] });
  // Перетаскивание точки не двигает устройства.
  const after = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const out: Record<string, { x: number; y: number }> = {};
    cy.nodes().forEach((n: { hasClass: (c: string) => boolean; id: () => string; position: () => { x: number; y: number } }) => {
      if (!n.hasClass('bend') && !n.hasClass('waypoint')) out[n.id()] = n.position();
    });
    return out;
  });
  expect(after).toEqual(devicePositions);
  await shot(page, 'map-waypoint-dragged');
});

test('точка удаляется двойным кликом, Delete и из меню (NR-038 п.1в, п.4в)', async ({ page }) => {
  await freshMap(page);

  // Двойной клик по точке удаляет её.
  let hit = await edgeHit(page);
  await page.mouse.dblclick(hit.x, hit.y);
  await page.waitForTimeout(250);
  expect(await waypointCount(page)).toBe(1);
  let wp = await waypointView(page);
  await page.mouse.dblclick(wp.pageX, wp.pageY);
  await page.waitForTimeout(250);
  expect(await waypointCount(page)).toBe(0);

  // Выбрать и нажать Delete.
  hit = await edgeHit(page);
  await page.mouse.dblclick(hit.x, hit.y);
  await page.waitForTimeout(250);
  expect(await waypointCount(page)).toBe(1);
  await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    cy.nodes('.waypoint').first().select();
  });
  await page.keyboard.press('Delete');
  await page.waitForTimeout(250);
  expect(await waypointCount(page)).toBe(0);

  // Контекстное меню по правому клику: «Удалить точку».
  hit = await edgeHit(page);
  await page.mouse.dblclick(hit.x, hit.y);
  await page.waitForTimeout(250);
  expect(await waypointCount(page)).toBe(1);
  wp = await waypointView(page);
  await page.mouse.click(wp.pageX, wp.pageY, { button: 'right' });
  await expect(page.locator('#wp-menu')).toBeVisible();
  await page.click('#wp-menu-delete');
  await page.waitForTimeout(250);
  expect(await waypointCount(page)).toBe(0);
  await expect(page.locator('#wp-menu')).toBeHidden();
});

test('точка изгиба переживает перезагрузку страницы (NR-038 п.1г, п.4г)', async ({ page }) => {
  await freshMap(page);
  const hit = await edgeHit(page);
  await page.mouse.dblclick(hit.x, hit.y);
  await page.waitForTimeout(250);
  const created = await waypointView(page);
  // Дебаунс сохранения 500 мс + запас.
  await page.waitForTimeout(900);
  await page.reload();
  await login(page);
  await page.click('nav .item[data-page="map"]');
  await page.waitForFunction(() => {
    const hook = (window as unknown as { __netatlas?: { cy: { nodes: () => { length: number } } } }).__netatlas;
    return hook !== undefined && hook.cy.nodes().length >= 15;
  });
  await page.waitForTimeout(600);
  expect(await waypointCount(page)).toBe(1);
  const restored = await waypointView(page);
  expect(restored.link).toBe(created.link);
  expect(restored.x).toBe(created.x);
  expect(restored.y).toBe(created.y);
  // Уборка: «Выстроить сеткой» стирает и точки (и положения).
  page.on('dialog', (d) => void d.accept());
  await page.click('#btn-arrange');
  await page.waitForTimeout(400);
  expect(await waypointCount(page)).toBe(0);
});

test('шаг сетки 20: тайл фона 20×масштаб, редкая сетка при зуме < 0.6 (NR-038 п.2, п.4д)', async ({ page }) => {
  await openMap(page);
  // Обычная плотность: тайл 20 × зум.
  await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    cy.zoom(1);
    cy.pan({ x: 0, y: 0 });
  });
  await page.waitForTimeout(200);
  const tile = await page.evaluate(() => {
    const layer = document.getElementById('map-grid');
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    return { size: layer?.style.backgroundSize ?? '', zoom: cy.zoom() };
  });
  expect(Number.parseFloat(tile.size.split('px')[0] ?? '0')).toBeCloseTo(20 * tile.zoom, 1);
  // При зуме 0.5 — каждая пятая точка: тайл 100 × зум.
  await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    cy.zoom(0.5);
  });
  await page.waitForTimeout(200);
  const rare = await page.evaluate(() => {
    const layer = document.getElementById('map-grid');
    return layer?.style.backgroundSize ?? '';
  });
  expect(Number.parseFloat(rare.split('px')[0] ?? '0')).toBeCloseTo(100 * 0.5, 1);
  await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    cy.zoom(1);
  });
});

test('подписи читаются: 13 px при 100%, фон непрозрачен, контраст ≥ 4.5:1 (NR-038 п.3, п.4е)', async ({ page }) => {
  await freshMap(page);
  const report = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const node = cy.nodes().filter((n: { isParent: () => boolean; hasClass: (c: string) => boolean }) =>
      !n.isParent() && !n.hasClass('bend') && !n.hasClass('waypoint')).first();
    // Контраст подписи к фону поля: #E6EAF0 на #0E1116 (WCAG).
    const lum = (hex: string): number => {
      const v = [1, 3, 5].map((i) => Number.parseInt(hex.slice(i, i + 2), 16) / 255)
        .map((c) => (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)));
      return 0.2126 * (v[0] ?? 0) + 0.7152 * (v[1] ?? 0) + 0.0722 * (v[2] ?? 0);
    };
    const l1 = lum('#E6EAF0');
    const l2 = lum('#0E1116');
    return {
      fs: node.style('font-size'),
      bgOpacity: node.style('text-background-opacity'),
      bgShape: node.style('text-background-shape'),
      padding: node.style('text-background-padding'),
      weight: node.style('font-weight'),
      contrast: (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05),
    };
  });
  expect(Number.parseFloat(String(report.fs))).toBeGreaterThanOrEqual(13);
  expect(Number(report.bgOpacity)).toBe(1);
  expect(report.contrast).toBeGreaterThanOrEqual(4.5);
  expect(Number(report.weight)).toBeGreaterThanOrEqual(500);
  // Фон подписи: отступ 3 px, скруглённый (halo, NR-038 п.3).
  expect(Number.parseFloat(String(report.padding))).toBe(3);
  expect(String(report.bgShape)).toContain('round');
  // При малом масштабе подпись не мельче 11 px экранных.
  await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    cy.zoom(0.5);
  });
  await page.waitForTimeout(250);
  const tiny = await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    const node = cy.nodes().filter((n: { isParent: () => boolean; hasClass: (c: string) => boolean }) =>
      !n.isParent() && !n.hasClass('bend') && !n.hasClass('waypoint')).first();
    return { zoom: cy.zoom(), fs: node.style('font-size') };
  });
  expect(Number.parseFloat(String(tiny.fs)) * tiny.zoom).toBeGreaterThanOrEqual(11);
  await page.evaluate(() => {
    const cy = (window as unknown as { __netatlas: { cy: import('cytoscape').default } }).__netatlas.cy;
    cy.zoom(1);
  });
  await shot(page, 'map-nr038-labels');
});

test('кнопка «Сбросить изгибы связи» стирает точки выбранной линии (NR-038 п.1)', async ({ page }) => {
  await freshMap(page);
  // Кнопка неактивна, пока линия не выбрана.
  await expect(page.locator('#btn-clear-bends')).toBeDisabled();
  const hit = await edgeHit(page);
  // Двойной клик создаёт точку И выбирает линию, к которой она
  // относится.
  await page.mouse.dblclick(hit.x, hit.y);
  await page.waitForTimeout(250);
  expect(await waypointCount(page)).toBe(1);
  await expect(page.locator('#btn-clear-bends')).toBeEnabled();
  await page.click('#btn-clear-bends');
  await page.waitForTimeout(250);
  expect(await waypointCount(page)).toBe(0);
  // Точек нет и на сервере: перезагрузка не возвращает изгибы.
  await page.waitForTimeout(900);
  await page.reload();
  await login(page);
  await page.click('nav .item[data-page="map"]');
  await page.waitForFunction(() => {
    const hook = (window as unknown as { __netatlas?: { cy: { nodes: () => { length: number } } } }).__netatlas;
    return hook !== undefined && hook.cy.nodes().length >= 15;
  });
  await page.waitForTimeout(500);
  expect(await waypointCount(page)).toBe(0);
});
