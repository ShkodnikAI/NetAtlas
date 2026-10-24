#!/usr/bin/env bash
# Мутационные проверки NR-012: ослабление любого условия приватности
# ловится тестами — белый список полей, фильтр доменов, проверка
# включения, исключение администраторов.
set -u
cd /home/z/my-project/netatlas
export PATH=$HOME/tools/go/bin:$PATH

ACT=agent/activity/activity.go
BACKUP=$(mktemp /tmp/nr012_activity_backup.XXXXXX)
cp "$ACT" "$BACKUP"
trap 'cp "$BACKUP" "$ACT"; rm -f "$BACKUP"' EXIT

pass=0; fail=0

mutate() {
  local name="$1" find="$2" replace="$3" testname="$4"
  cp "$BACKUP" "$ACT"
  python3 - "$ACT" "$find" "$replace" <<'PYEOF'
import sys
p, find, replace = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(p).read()
assert find in src, f"фрагмент не найден: {find}"
src = src.replace(find, replace, 1)
open(p, 'w').write(src)
PYEOF
  if go test ./agent/activity/ ./server/api/ -run "$testname" > /dev/null 2>&1; then
    echo "MUTANT ВЫЖИЛ [$name]: тест $testname прошёл на ослабленном коде"
    fail=$((fail+1))
  else
    echo "поймано [$name] → $testname"
    pass=$((pass+1))
  fi
  cp "$BACKUP" "$ACT"
}

# M1: фильтр домена пропускает всё (пути/пароли в URL).
mutate "domain-filter" \
  '	if len(s) == 0 || len(s) > MaxDomainLen || !hostRe.MatchString(s) {
		return ""
	}
	return s' \
  '	return s' \
  'TestExtractHost'

# M2: администраторы собираются (исключения игнорируются).
mutate "admin-excluded" \
  '	local := localAccount(account)
	for _, ex := range p.ExcludeAccounts {
		if strings.EqualFold(localAccount(ex), local) {
			return false
		}
	}
	return true' \
  '	_ = localAccount(account)
	return true' \
  'TestPolicyExcludesAdmins'

# M3: белый список приложений не проверяется (Validate ослаблен).
mutate "app-whitelist" \
  '	for a := range r.Apps {
		if sanitizeProcess(a) != a {
			return errors.New("activity: имя приложения не нормализовано (путь или лишние символы)")
		}
	}' \
  '	_ = r.Apps' \
  'TestReportValidate'

# M4: лимиты агрегата сняты (пределы имён/доменов).
mutate "limits" \
  '	if len(r.Apps) > MaxAppNames || len(r.Domains) > MaxDomains {
		return errors.New("activity: слишком много имён в агрегате")
	}' \
  '	_ = MaxAppNames' \
  'TestReportValidate'

# M5: простой считается активностью (порог снят).
mutate "idle-threshold" \
  '	if idleMS > 60_000 {
		// Долгое отсутствие ввода — простой: ни активности, ни
		// приложения, ни доменов в это окно не добавляется.
		c.idleMS += SnapshotInterval.Milliseconds()
		return
	}' \
  '	_ = idleMS' \
  'TestCollectorAggregates'

cp "$BACKUP" "$ACT"
if [ "$(git diff --stat -- "$ACT" | wc -l)" != "0" ]; then
  echo "ПРОВАЛ: activity.go не восстановлен побайтово"
  exit 1
fi

echo "=== Мутации NR-012: поймано $pass, выжило $fail ==="
[ "$fail" = "0" ] || exit 1
echo "Все мутанты пойманы."
