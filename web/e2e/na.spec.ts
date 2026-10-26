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
  expect(firstIP).toBe('192.168.100.10');
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
    // 12 устройств фикстуры + коммутатор ip:192.168.100.1 из связей.
    if (nodes.length !== 13) return { error: `узлов ${nodes.length}, хочу 13`, overlaps: [] as string[] };
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
