// Конфигурация сквозных тестов интерфейса (Playwright, NR-031):
// Chromium против собранного netatlas-server с фикстурой из
// web/e2e/seed (12 устройств, длинные MAC, подсеть 192.168.100.0/24).
import { defineConfig } from '@playwright/test';

const PORT = process.env.NETATLAS_E2E_PORT ?? '18484';

export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  outputDir: './e2e-results',
  fullyParallel: false,
  workers: 1,
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    viewport: { width: 1440, height: 900 },
  },
  webServer: {
    command: 'node ./e2e/start-server.mjs',
    url: `http://127.0.0.1:${PORT}/app.css`,
    reuseExistingServer: !process.env.CI,
    timeout: 90_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
