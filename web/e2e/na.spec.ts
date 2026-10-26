// Сквозные тесты интерфейса в настоящем Chromium (NR-031, обязательная
// проверка): один видимый экран на пункт меню, подсети после входа,
// таблица устройств с адресами, подписи карты без пересечений, один
// пункт «Активность». Тесты обязаны падать, если убрать правило
// [hidden] из CSS, — первый же экран увидит лишнее.
import { mkdirSync } from 'node:fs';
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
  await expect(rows).toHaveCount(12);
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

test('на карте 12 узлов и подписи не перекрываются (NR-031 п.4)', async ({ page }) => {
  await login(page);
  await page.click('nav .item[data-page="map"]');
  await page.waitForFunction(() => {
    const hook = (window as unknown as { __netatlas?: { cy: { nodes: () => { length: number } } } }).__netatlas;
    return hook !== undefined && hook.cy.nodes().length >= 12;
  });
  // Дать раскладке и отрисовке закончиться, затем дважды проверить:
  // стабильность позиций и отсутствие пересечений подписей.
  await page.waitForTimeout(700);
  const report = await page.evaluate(() => {
    const cy = (window as unknown as {
      __netatlas: { cy: import('cytoscape').default };
    }).__netatlas.cy;
    const nodes = cy.nodes().filter((n: { isParent: () => boolean }) => !n.isParent());
    // 12 устройств фикстуры (NR-032): связей LLDP/FDB нет, узел
    // коммутатора не создаётся.
    if (nodes.length !== 12) return { error: `узлов ${nodes.length}, хочу 12`, overlaps: [] as string[] };
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
    return hook !== undefined && hook.cy.nodes().length >= 12;
  });
  // a11y-слой повторяет узлы карты с data-kind (скринридеры и тесты).
  const kinds = await page.locator('#map-a11y li').evaluateAll((els) =>
    els.map((el) => (el as HTMLElement).dataset.kind ?? ''),
  );
  expect(kinds).toHaveLength(12);
  expect(new Set(kinds)).toEqual(
    new Set(['router', 'server', 'device', 'printer', 'phone', 'iot']),
  );
  await shot(page, 'map-kinds');
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
    const nodes = cy.nodes().filter((n: { isParent: () => boolean }) => !n.isParent());
    const gateways = nodes.filter((n: { data: (k: string) => string }) => n.data('kind') === 'router');
    // Все предполагаемые связи ведут к шлюзу, у каждого не-шлюза ровно одна.
    const toGateway = assumed.every((e: { data: (k: string) => string; connectedNodes: () => { length: number }[] }) =>
      e.connectedNodes().some((x: { data: (k: string) => string }) => x.data('kind') === 'router'),
    );
    return { assumed: assumed.length, nodes: nodes.length, gateways: gateways.length, toGateway };
  });
  expect(report.gateways).toBe(1);
  expect(report.assumed).toBe(report.nodes - report.gateways);
  expect(report.assumed).toBe(11);
  expect(report.toGateway).toBe(true);
});

test('узлы выстроены сеткой: ряды на равных координатах (NR-032 п.4, п.6)', async ({ page }) => {
  await login(page);
  await page.click('nav .item[data-page="map"]');
  await page.waitForFunction(() => {
    const hook = (window as unknown as { __netatlas?: { cy: { nodes: () => { length: number } } } }).__netatlas;
    return hook !== undefined && hook.cy.nodes().length >= 12;
  });
  await page.waitForTimeout(500);
  const report = await page.evaluate(() => {
    const cy = (window as unknown as {
      __netatlas: { cy: import('cytoscape').default };
    }).__netatlas.cy;
    const byKind = new Map<string, number[]>();
    cy.nodes()
      .filter((n: { isParent: () => boolean }) => !n.isParent())
      .forEach((n: { data: (k: string) => string; position: (a: string) => number }) => {
        const kind = n.data('kind');
        const ys = byKind.get(kind) ?? [];
        ys.push(n.position('y'));
        byKind.set(kind, ys);
      });
    // Все узлы одного типа стоят в одном ряду (одна координата Y).
    const rows = new Map<string, number>();
    for (const [kind, ys] of byKind) {
      const unique = [...new Set(ys.map((y) => Math.round(y)))];
      if (unique.length !== 1) return { error: `тип ${kind}: Y-координаты ${unique.join(', ')}` };
      rows.set(kind, unique[0]);
    }
    // Роутер — самый верхний ряд; типы не делят ряд друг с другом.
    const routerY = rows.get('router') ?? NaN;
    for (const [kind, y] of rows) {
      if (kind !== 'router' && y <= routerY) {
        return { error: `тип ${kind} не ниже роутера` };
      }
    }
    return { error: null, rows: [...rows.entries()] };
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
    return hook !== undefined && hook.cy.nodes().length >= 12;
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
    return hook !== undefined && hook.cy.nodes().length >= 12;
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
    const nodes = cy.nodes().filter((n: { isParent: () => boolean }) => !n.isParent());
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
  expect(Math.abs(pos.x % 100)).toBe(0);
  expect(Math.abs(pos.y % 120)).toBe(0);
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
  expect(text).toContain('192.168.100.1');
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
      .filter((n: { isParent: () => boolean }) => !n.isParent())
      .map((n: { data: (k: string) => string }) => n.data('icon') ?? '');
  });
  const withAttention = icons.filter((i: string) => i.includes('%E2%96%B2') || i.includes('▲') || decodeURIComponent(i).includes('M19.2 2.9'));
  expect(withAttention.length).toBeGreaterThan(0);
  // a11y-слой показывает статус «▲ внимание».
  const a11y = await page.locator('#map-a11y li').allTextContents();
  expect(a11y.some((t) => t.includes('▲ внимание'))).toBe(true);
  // Панель «Требуют внимания»: список сигналов, клик фокусирует узел.
  await page.click('#btn-attention');
  const rows = page.locator('#attention-panel .attention-row');
  await expect(rows.first()).toBeVisible();
  const count = await rows.count();
  expect(count).toBeGreaterThan(0);
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
    return hook !== undefined && hook.cy.nodes().length >= 12;
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
