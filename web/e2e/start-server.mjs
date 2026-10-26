// Запуск netatlas-server для сквозных тестов интерфейса (NR-031):
// сначала сеется временная база (web/e2e/seed), затем стартует
// собранный сервер. Готовность — доступность /app.css.
//
// Переменные окружения:
//   NETATLAS_E2E_SERVER — путь к бинарнику netatlas-server (иначе
//                         собирается из исходников через go build);
//   NETATLAS_E2E_SEED   — путь к бинарнику seed (аналогично);
//   NETATLAS_E2E_PORT   — порт (по умолчанию 18484);
//   NETATLAS_E2E_TOKEN  — токен (по умолчанию e2e-token-local).
// Скрипт держит сервер запущенным, пока его не погасят (webServer
// Playwright убивает процесс после прогона).
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const port = process.env.NETATLAS_E2E_PORT ?? '18484';
const token = process.env.NETATLAS_E2E_TOKEN ?? 'netatlas-e2e-local-token-000';
const work = mkdtempSync(join(tmpdir(), 'netatlas-e2e-'));
const db = join(work, 'e2e.db');

function binary(name, envVar, pkg) {
  const fromEnv = process.env[envVar];
  if (fromEnv && fromEnv !== '') return fromEnv;
  const out = join(work, name);
  console.log(`e2e: собираю ${pkg} -> ${out}`);
  const res = spawnSync('go', ['build', '-o', out, pkg], { cwd: root, stdio: 'inherit' });
  if (res.status !== 0) {
    console.error(`e2e: не удалось собрать ${pkg} (нужен Go в PATH или ${envVar})`);
    process.exit(1);
  }
  return out;
}

const serverBin = binary('netatlas-server', 'NETATLAS_E2E_SERVER', './cmd/netatlas-server');
const seedBin = binary('seed', 'NETATLAS_E2E_SEED', './web/e2e/seed');

const seeded = spawnSync(seedBin, [db], { stdio: 'inherit' });
if (seeded.status !== 0) {
  console.error('e2e: сеялка фикстуры упала');
  process.exit(1);
}

const server = spawn(
  serverBin,
  ['--listen', `127.0.0.1:${port}`, '--db', db, '--subnets', '192.168.100.0/24'],
  { env: { ...process.env, NETATLAS_TOKEN: token }, stdio: 'inherit' },
);
server.on('exit', (code) => {
  console.error(`e2e: сервер завершился с кодом ${code}`);
  process.exit(code ?? 1);
});
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    server.kill(sig);
  });
}

// Готовность: /app.css отдаётся без токена (статика).
const deadline = Date.now() + 30_000;
while (Date.now() < deadline) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/app.css`);
    if (res.ok) {
      console.log(`e2e: сервер готов на http://127.0.0.1:${port}`);
      break;
    }
  } catch {
    // ещё не слушает
  }
  await new Promise((r) => setTimeout(r, 200));
  if (Date.now() >= deadline) {
    console.error('e2e: сервер не поднялся за 30 секунд');
    server.kill('SIGTERM');
    process.exit(1);
  }
}
