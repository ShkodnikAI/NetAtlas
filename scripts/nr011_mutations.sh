#!/usr/bin/env bash
# Мутационные проверки NR-011: каждая проверка шлюза pipeline/gate
# ослабляется по очереди — тесты обязаны упасть, иначе мутант выжил.
# Побайтовое восстановление gate.go после каждой мутации.
set -u
cd /home/z/my-project/netatlas
export PATH=$HOME/tools/go/bin:$PATH

GATE=pipeline/gate/gate.go
BACKUP=$(mktemp /tmp/nr011_gate_backup.XXXXXX)
cp "$GATE" "$BACKUP"
trap 'cp "$BACKUP" "$GATE"; rm -f "$BACKUP"' EXIT

pass=0; fail=0

mutate() {
  local name="$1" find="$2" replace="$3" testname="$4"
  cp "$BACKUP" "$GATE"
  python3 - "$GATE" "$find" "$replace" <<'PYEOF'
import sys
p, find, replace = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(p).read()
assert find in src, f"фрагмент не найден для мутации: {find}"
src = src.replace(find, replace, 1)
open(p, 'w').write(src)
PYEOF
  if go test ./pipeline/gate/ -run "$testname" > /dev/null 2>&1; then
    echo "MUTANT ВЫЖИЛ [$name]: тест $testname прошёл на ослабленном шлюзе"
    fail=$((fail+1))
  else
    echo "поймано [$name] → $testname"
    pass=$((pass+1))
  fi
  cp "$BACKUP" "$GATE"
}

# M1: диспетчеризация включена принудительно.
mutate "dispatch-disabled" \
  'if !j.DispatchEnabled {' \
  'if false && !j.DispatchEnabled {' \
  'TestCanDispatchRejectsDispatchDisabled'

# M2: статус ниже tested пропускается.
mutate "status-too-low" \
  'if !AtLeast(s.Status, StatusTested) {' \
  'if false && !AtLeast(s.Status, StatusTested) {' \
  'TestCanDispatchRejectsStatusBelowTested'

# M3: неподписанный пропускается.
mutate "not-signed" \
  'if s.SignedBy == "" {' \
  'if false && s.SignedBy == "" {' \
  'TestCanDispatchRejectsUnsigned'

# M4: изменённый после подписи пропускается.
mutate "content-changed" \
  'if s.SignedSHA != s.SHA256 {' \
  'if false && s.SignedSHA != s.SHA256 {' \
  'TestCanDispatchRejectsContentChanged'

# M5: просроченная подпись пропускается.
mutate "signature-expired" \
  'if !s.SignExpires.After(now) {' \
  'if false && !s.SignExpires.After(now) {' \
  'TestCanDispatchRejectsExpiredSignature'

# M6: цель вне разрешённого набора пропускается.
mutate "target-not-allowed" \
  'if !contains(j.Targets, j.Target) {' \
  'if false && !contains(j.Targets, j.Target) {' \
  'TestCanDispatchRejectsForeignTarget'

# M7: драйвер без пилота пропускается.
mutate "pilot-required" \
  'if (s.Category == CategoryDriver || s.Category == CategoryNic) && !s.PilotPassed && !j.IsPilot {' \
  'if false && (s.Category == CategoryDriver || s.Category == CategoryNic) && !s.PilotPassed && !j.IsPilot {' \
  'TestCanDispatchRejectsDriverWithoutPilot'

# M8: произвольные скрипты без права пропускаются.
mutate "custom-scripts" \
  'if s.Kind == KindScript && !j.AllowCustomScripts {' \
  'if false && s.Kind == KindScript && !j.AllowCustomScripts {' \
  'TestCanDispatchRejectsCustomScriptsDisabled'

# M9: переходы статусов вне цепочки разрешаются.
mutate "can-advance-chain" \
  'if to != next {' \
  'if false && to != next {' \
  'TestCanAdvanceOnlyForward'

# M10: rejected теряет статус конечного (возврат из него разрешён).
mutate "rejected-terminal" \
  'if from == StatusRejected {' \
  'if false && from == StatusRejected {' \
  'TestCanAdvanceOnlyForward'

cp "$BACKUP" "$GATE"
if [ "$(git diff --stat -- "$GATE" | wc -l)" != "0" ]; then
  echo "ПРОВАЛ: gate.go не восстановлен побайтово"
  exit 1
fi

echo "=== Мутации NR-011: поймано $pass, выжило $fail ==="
[ "$fail" = "0" ] || exit 1
echo "Все мутанты пойманы."
