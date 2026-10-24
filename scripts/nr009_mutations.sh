#!/bin/bash
# NR-009: мутационное тестирование rules (пороги, прогноз) и store.
# Наряд требует: сломать направление сравнения порога и формулу
# наклона — тесты обязаны падать.
set -u
export PATH=$HOME/tools/go/bin:$PATH
cd "$(dirname "$0")/.."

FAIL=0
RAN=0
declare -A BACKUPS
ONLY=("$@")

backup() {
    if [ -z "${BACKUPS[$1]:-}" ]; then
        BAK="/tmp/nr009_$(echo "$1" | tr '/' '_').bak"
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

run() {
    if [ ${#ONLY[@]} -gt 0 ]; then
        MATCH=0
        for PAT in "${ONLY[@]}"; do
            case "$1" in *"$PAT"*) MATCH=1 ;; esac
        done
        if [ "$MATCH" = "0" ]; then return 0; fi
    fi
    F="$4"
    RAN=$((RAN+1))
    backup "$F"
    mutate_file "$F" "$5"
    if ! go test "$2" -count=1 -run "$3" >/tmp/nr009_mut.log 2>&1; then
        echo "M($1): поймана — $3 красный"
    else
        echo "M($1): НЕ поймана — $3 зелёный!!!"
        FAIL=1
    fi
    cp "${BACKUPS[$F]}" "$F"
}

# --- rules: пороги ---

# M1: направление сравнения износа сломано.
run "M1 сравнение износа перевёрнуто" ./rules/ "TestRuleSSDWear" rules/evaluate.go \
    's = s.replace("if d.Wear == nil || *d.Wear <= limit {", "if d.Wear == nil || *d.Wear >= limit {")'

# M2: свободное место — сравнение перевёрнуто.
run "M2 сравнение свободного места перевёрнуто" ./rules/ "TestRuleVolumeFree" rules/evaluate.go \
    's = s.replace("if freePct >= freeLimit {", "if freePct <= freeLimit {")'

# M3: срок обновлений — сравнение перевёрнуто.
run "M3 сравнение устаревания перевёрнуто" ./rules/ "TestRuleUpdatesStale" rules/evaluate.go \
    's = s.replace("if days <= staleDays {", "if days >= staleDays {")'

# M4: поколение Intel — деление не то.
run "M4 поколение Intel делится неверно" ./rules/ "TestRuleCPUGeneration" rules/evaluate.go \
    's = s.replace("return n / 1000", "return n / 100")'

# --- rules: прогноз ---

# M5: формула наклона сломана (знак).
run "M5 наклон с обратным знаком" ./rules/ "TestForecastRisingKnownSlope" rules/forecast.go \
    's = s.replace("slope := (n*sxy - sx*sy) / denom", "slope := (sx*sy - n*sxy) / denom")'

# M6: R²-фильтр снят — шум выдаёт прогноз.
run "M6 фильтр R² снят" ./rules/ "TestForecastNoisy" rules/forecast.go \
    's = s.replace("if r2 < MinR2 {", "if false {")'

# M7: минимум точек снижен.
run "M7 минимум точек снижен" ./rules/ "TestForecastFewPoints" rules/forecast.go \
    's = s.replace("const MinPoints = 7", "const MinPoints = 2")'

# M8: обрезка истории до 30 дней сломана.
run "M8 обрезка истории сломана" ./rules/ "TestForecastTrimsTo30" rules/forecast.go \
    's = s.replace("""	if len(points) > 30 {
		points = points[len(points)-30:]
	}""", """	if len(points) > 5 {
		points = points[len(points)-5:]
	}""")'

# --- rules: загрузчик и таблицы ---

# M9: требование source снято — правила без источника принимаются.
run "M9 требование source снято" ./rules/ "TestLoaderRejectsRuleWithoutSource" rules/engine.go \
    's = s.replace("""	if len(r.Source) == 0 {
		return fmt.Errorf("правило %s: нет source — отвергнуто", r.ID)
	}""", "")'

# M10: переопределение каталогом игнорируется.
run "M10 --rules-dir игнорируется" ./rules/ "TestRulesDirOverride" rules/engine.go \
    's = s.replace("""	fsys := os.DirFS(dir)""", """	fsys := dataFS
	_ = dir
	base := "data"
	dir2 := base
	_ = dir2""")'
# (M10 требует правки вызова loadFS: патч ломает загрузку каталога —
# проверяем, что тест ловит именно это; при сборке подставим вручную)

# M11: смягчение непроверенных строк снято.
run "M11 смягчение unverified снято" ./rules/ "TestRuleUnverifiedCapped" rules/evaluate.go \
    's = s.replace("""		severity := r.Severity
		if !verified {
			severity = SeverityInfo
		}
		rule := r
		rule.Severity = severity
		fact := fmt.Sprintf("%s: поддержка закончилась %s", name, eol.Format("2006-01-02"))""", """		rule := r
		fact := fmt.Sprintf("%s: поддержка закончилась %s", name, eol.Format("2006-01-02"))""")'

# --- store ---

# M12: upsert дневной точки сломан (дубли за день).
run "M12 upsert дневной точки сломан" ./server/api/ "TestDiskHistoryStore" server/store/disks.go \
    's = s.replace("""			 ON CONFLICT(agent_id, drive, day) DO UPDATE SET
				used_bytes = excluded.used_bytes,
				capacity_bytes = excluded.capacity_bytes""", "")'

# Контроль: файлы восстановлены побайтово.
for F in "${!BACKUPS[@]}"; do
    if ! cmp -s "${BACKUPS[$F]}" "$F"; then
        echo "ВОССТАНОВЛЕНИЕ СЛОМАНО: $F"
        FAIL=1
    fi
done

if [ "$FAIL" = "0" ]; then
    echo "Пойманы все запущенные мутации: $RAN."
    exit 0
fi
echo "Есть непойманные мутации!"
exit 1
