#!/bin/bash
# NR-010: мутационное тестирование оценки безопасности. Каждая
# мутация обязана уронить хотя бы один тест; после прогона файлы
# восстанавливаются побайтово.
set -u
export PATH=$HOME/tools/go/bin:$PATH
cd "$(dirname "$0")/.."

FAIL=0
declare -A BACKUPS

backup() {
    if [ -z "${BACKUPS[$1]:-}" ]; then
        BAK="/tmp/nr010_$(echo "$1" | tr '/' '_').bak"
        cp "$1" "$BAK"
        BACKUPS[$1]="$BAK"
    fi
}

mutate_file() {
    python3 - "$1" <<EOF
import sys
p = sys.argv[1]
s = open(p).read()
$2
open(p, "w").write(s)
EOF
}

run() { # имя, пакет, тест, файл, патч
    F="$4"
    backup "$F"
    mutate_file "$F" "$5"
    if ! go test "$2" -count=1 -run "$3" >/tmp/nr010_mut.log 2>&1; then
        echo "M($1): поймана — $3 красный"
    else
        echo "M($1): НЕ поймана — $3 зелёный!!!"
        FAIL=1
    fi
    cp "${BACKUPS[$F]}" "$F"
}

# M1: вес замечания снижен 25→5 — тесты оценки обязаны упасть.
run "M1 вес smbv1 25→5" ./rules/security/ "TestScoreBoundaries|TestEvaluateChecksFailOnly" rules/data/security_weights.json \
    's = s.replace("""    "sec_smbv1_enabled": {
      "severity": "critical",
      "weight": 25,""", """    "sec_smbv1_enabled": {
      "severity": "critical",
      "weight": 5,""")'

# M2: запрет Set-* снят в тесте только-чтения — мутация вписывает
# Set-SmbServerConfiguration в разрешённые; тест с фикстурой-нарушителем
# обязан упасть. Мутируем сам список запрещённых глаголов.
run "M2 Set- исключён из запрещённых" ./agent/checks/ "TestScriptsAreReadOnlyMutant" agent/checks/read_only_test.go \
    's = s.replace("var forbiddenVerbs = []string{\n\t\"Set\", ", "var forbiddenVerbs = []string{\n\t")'

# M3: unknown считается «безопасно» (fail-only снят) — тест обязан упасть.
run "M3 unknown даёт замечание" ./rules/security/ "TestEvaluateChecksFailOnly|TestEvaluateChecksUnknownIsNotSafe" rules/security/security.go \
    's = s.replace("if res.Status != checks.StatusFail {", "if res.Status == checks.StatusPass {")'

# M4: оценка не ограничена нулём — тест границы обязан упасть.
run "M4 без clamp" ./rules/security/ "TestScoreBoundaries" rules/security/security.go \
    's = s.replace("""	if total < 0 {
		return 0
	}""", "")'

# M5: порог версии «строго меньше» заменён на «меньше или равно» —
# граница «ровно минимум — не замечание» обязана упасть.
run "M5 версия <= минимума" ./rules/security/ "TestEvaluateSoftware" rules/security/security.go \
    's = s.replace("if versionLess(ver, minVer) {", "if !versionLess(minVer, ver) {")'

# M6: статус fail-проверки подменён на pass при приёме — тест приёма обязан упасть.
run "M6 обработчик любит любой статус" ./server/agentapi/ "TestSecurityDenies" server/agentapi/agentapi.go \
    's = s.replace("case res.Status != \"pass\" && res.Status != \"fail\" && res.Status != \"unknown\":", "case false:")'

# M7: white-list тест ослаблен (запрет перестаёт искать глаголы) —
# проверка-мутант обязан стать зелёной и быть пойманной отдельным тестом.
run "M7 forbiddenIn всегда пуст" ./agent/checks/ "TestScriptsAreReadOnlyMutant" agent/checks/read_only_test.go \
    's = s.replace("func forbiddenIn(script, name string) []string {", "func forbiddenIn(script, name string) []string {\n\treturn nil")'

if [ "$FAIL" -eq 0 ]; then
    echo "все мутации пойманы"
else
    echo "есть непойманные мутации"
    exit 1
fi
