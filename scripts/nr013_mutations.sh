#!/usr/bin/env bash
# Мутационные проверки NR-013: снятие любого шага очистки, маркировки
# внедрений, обёртки недоверенных данных или лимита ответа ловится
# тестами границы ИИ.
set -u
cd /home/z/my-project/netatlas
export PATH=$HOME/tools/go/bin:$PATH

FILES=(reports/sanitize.go reports/injection.go reports/report.go server/store/reports.go)
declare -A BACKUP
for f in "${FILES[@]}"; do BACKUP[$f]=$(mktemp /tmp/nr013_backup.XXXXXX); cp "$f" "${BACKUP[$f]}"; done
restore() { for f in "${FILES[@]}"; do cp "${BACKUP[$f]}" "$f"; rm -f "${BACKUP[$f]}"; done; }
trap restore EXIT

pass=0; fail=0

mutate() {
  local name="$1" file="$2" find="$3" replace="$4" testname="$5"
  for f in "${FILES[@]}"; do cp "${BACKUP[$f]}" "$f"; done
  python3 - "$file" "$find" "$replace" <<'PYEOF'
import sys
p, find, replace = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(p).read()
assert find in src, f"фрагмент не найден: {find}"
src = src.replace(find, replace, 1)
open(p, 'w').write(src)
PYEOF
  if go test ./reports/ ./server/api/ ./server/store/ -count=1 -run "$testname" > /dev/null 2>&1; then
    echo "МУТАНТ ВЫЖИЛ [$name]: тест $testname прошёл на ослабленном коде"
    fail=$((fail+1))
  else
    echo "поймано [$name] → $testname"
    pass=$((pass+1))
  fi
}

# M1: Bearer-токены не вырезаются.
mutate "bearer-kept" reports/sanitize.go \
'	text = bearerRe.ReplaceAllStringFunc(text, func(s string) string {
		return "[REDACTED]"
	})' \
'	_ = bearerRe' \
'TestSanitizeRemovesAllSecrets'

# M2: пары password=/pwd=/token= не вырезаются.
mutate "secret-pairs-kept" reports/sanitize.go \
'	text = secretPairRe.ReplaceAllStringFunc(text, func(s string) string {
		i := strings.IndexAny(s, "=:")
		return s[:i+1] + " [REDACTED]"
	})' \
'	_ = secretPairRe' \
'TestSanitizeRemovesAllSecrets'

# M3: IPv4 не заменяются псевдонимами.
mutate "ipv4-kept" reports/sanitize.go \
'	text = ipv4Re.ReplaceAllStringFunc(text, func(s string) string {
		return m.alias("ip", s, "IP")
	})' \
'	_ = ipv4Re' \
'TestSanitizeRemovesAllSecrets'

# M4: имена компьютеров из справочника не заменяются.
mutate "hosts-kept" reports/sanitize.go \
'		text = strings.ReplaceAll(text, host, m.alias("host", host, "HOST"))' \
'		text = strings.ReplaceAll(text, host, host)' \
'TestSanitizeRemovesAllSecrets|TestReportBoundary'

# M5: псевдонимы нестабильны (кэш соответствий снят).
mutate "alias-unstable" reports/sanitize.go \
'	if a, ok := m.index[key]; ok {
		return a
	}' \
'	_ = key' \
'TestSanitizeRemovesAllSecrets'

# M6: фразы-инъекции не помечаются (молча пропускаются).
mutate "injection-silent" reports/injection.go \
'			if re.MatchString(line) {' \
'			if false && re.MatchString(line) {' \
'TestInjectionsMarked|TestReportBoundary'

# M7: обёртка недоверенных данных снята.
mutate "wrapdata-off" reports/injection.go \
'	return dataBlockOpen + " " + strings.TrimRight(text, "\n") + " " + dataBlockClose' \
'	_, _ = dataBlockOpen, dataBlockClose
	return strings.TrimRight(text, "\n")' \
'TestBuildLimits|TestInjectionsMarked'

# M8: лимит ответа ИИ (32 КБ) снят.
mutate "answer-limit-off" server/store/reports.go \
'	if len(answer) > MaxAnswerBytes {' \
'	if len(answer) > 1<<30 {' \
'TestAIAnswerLimit'

echo "---"
echo "поймано: $pass / выжило: $fail"
[ "$fail" -eq 0 ]
