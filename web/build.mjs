// Сборка веб-интерфейса: bundle src/main.ts → dist/app.js, копия
// index.html и styles.css → dist/. Детерминированная: одна версия
// esbuild + одинаковый вход дают тот же вывод (CI проверяет
// git diff --exit-code web/dist).
import { build } from 'esbuild';
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, 'dist');
mkdirSync(dist, { recursive: true });

await build({
  entryPoints: [join(root, 'src/main.ts')],
  bundle: true,
  outfile: join(dist, 'app.js'),
  target: ['es2022'],
  format: 'iife',
  sourcemap: false,
  minify: false,
  logLevel: 'info',
  legalComments: 'none',
});

copyFileSync(join(root, 'index.html'), join(dist, 'index.html'));
copyFileSync(join(root, 'src/styles.css'), join(dist, 'app.css'));
copyFileSync(join(root, '..', 'docs/assets/logo-mark.png'), join(dist, 'logo-mark.png'));
console.log('сборка готова: web/dist');
