#!/usr/bin/env bash
# Мутационные проверки NR-025: пропуск agent/verify.Verify и пропуск
# проверки exec_enabled — тесты обязаны упасть (наряд: «Тесты должны
# падать, если пропустить Verify или флаг exec_enabled»).
set -u
cd /home/z/my-project/netatlas
export PATH=$HOME/tools/go/bin:$PATH

EXEC=agent/exec/exec.go
BACKUP=$(mktemp /tmp/nr025_exec_backup.XXXXXX)
cp "$EXEC" "$BACKUP"
trap 'cp "$BACKUP" "$EXEC"; rm -f "$BACKUP"' EXIT

pass=0; fail=0

mutate() {
  local name="$1" find="$2" replace="$3" testname="$4"
  cp "$BACKUP" "$EXEC"
  python3 - "$EXEC" "$find" "$replace" <<'PYEOF'
import sys
p, find, replace = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(p).read()
assert find in src, f"фрагмент не найден: {find}"
src = src.replace(find, replace, 1)
open(p, 'w').write(src)
PYEOF
  if go test ./agent/exec/ -run "$testname" > /dev/null 2>&1; then
    echo "MUTANT ВЫЖИЛ [$name]: тест $testname прошёл на ослабленном исполнителе"
    fail=$((fail+1))
  else
    echo "поймано [$name] → $testname"
    pass=$((pass+1))
  fi
  cp "$BACKUP" "$EXEC"
}

# M1: проверка подписи пропущена — изменённое/чужое исполнится.
mutate "skip-verify" \
  '	if err := verify.Verify(sj, d.PubKey, d.SelfID, d.Now(), d.Seen); err != nil {' \
  '	if false && func() error { return verify.Verify(sj, d.PubKey, d.SelfID, d.Now(), d.Seen) }() != nil {' \
  'TestProcessRejectsUnverified'

# M2: политика exec_enabled пропущена — выключенное исполнение сработает.
mutate "skip-exec-policy" \
  '	if !d.Enabled() {' \
  '	if false && !d.Enabled() {' \
  'TestProcessDisabledByPolicy'

cp "$BACKUP" "$EXEC"
if [ "$(git diff --stat -- "$EXEC" | wc -l)" != "0" ]; then
  echo "ПРОВАЛ: exec.go не восстановлен побайтово"
  exit 1
fi

echo "=== Мутации NR-025: поймано $pass, выжило $fail ==="
[ "$fail" = "0" ] || exit 1
echo "Все мутанты пойманы."
