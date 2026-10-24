#!/bin/bash
# NR-008: мутационное тестирование порогов качества и уплотнения.
set -u
export PATH=$HOME/tools/go/bin:$PATH
cd "$(dirname "$0")/.."

FAIL=0
RAN=0
declare -A BACKUPS
ONLY=("$@")

backup() {
    if [ -z "${BACKUPS[$1]:-}" ]; then
        BAK="/tmp/nr008_$(echo "$1" | tr '/' '_').bak"
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
    if ! go test "$2" -count=1 -run "$3" >/tmp/nr008_mut.log 2>&1; then
        echo "M($1): поймана — $3 красный"
    else
        echo "M($1): НЕ поймана — $3 зелёный!!!"
        FAIL=1
    fi
    cp "${BACKUPS[$F]}" "$F"
}

# --- пороги (rules/network.go) ---

# M1: порог потерь перевёрнут.
run "M1 порог потерь перевёрнут" ./rules/ "TestNetLossThresholds" rules/network.go \
    's = s.replace("if m.Kind != \"loss\" || m.Value <= limit/100 {", "if m.Kind != \"loss\" || m.Value >= limit/100 {")'

# M2: порог задержки шлюза перевёрнут.
run "M2 порог задержки перевёрнут" ./rules/ "TestNetGatewayLatency" rules/network.go \
    's = s.replace("if m.Kind != \"latency\" || m.Value <= limit {", "if m.Kind != \"latency\" || m.Value >= limit {")'

# M3: порог джиттера перевёрнут.
run "M3 порог джиттера перевёрнут" ./rules/ "TestNetJitter" rules/network.go \
    's = s.replace("if m.Kind != \"jitter\" || m.Value <= limit {", "if m.Kind != \"jitter\" || m.Value >= limit {")'

# M4: порог загрузки порта перевёрнут.
run "M4 порог загрузки порта перевёрнут" ./rules/ "TestNetPortUtil" rules/network.go \
    's = s.replace("if m.Kind != \"port_util\" || m.Value <= limit {", "if m.Kind != \"port_util\" || m.Value >= limit {")'

# M5: порог bufferbloat перевёрнут.
run "M5 порог bufferbloat перевёрнут" ./rules/ "TestNetBufferbloat" rules/network.go \
    's = s.replace("if m.Kind != \"bufferbloat\" || m.Value <= limit {", "if m.Kind != \"bufferbloat\" || m.Value >= limit {")'

# --- расчёты (agent/measure) ---

# M6: джиттер — не отклонение, а просто средняя разность.
run "M6 джиттер без квадрата" ./agent/measure/ "TestComputeSeries" agent/measure/measure.go \
    's = s.replace("return math.Sqrt(sq / float64(len(diffs)))", "return math.Abs(mean)")'

# M7: окно простоя сдвинуто (0-4 часа).
run "M7 окно простоя сдвинуто" ./agent/measure/ "TestInQuietHours" agent/measure/measure.go \
    's = s.replace("return h >= 1 && h < 5", "return h < 5")'

# M8: суточный лимит снят.
run "M8 суточный лимит снят" ./agent/measure/ "TestVolumeLimit" agent/measure/run.go \
    's = s.replace("if v.Used+n > v.Max {", "if false {")'

# M9: лимитер CPU не останавливает.
run "M9 лимитер CPU снят" ./agent/measure/ "TestLimiter" agent/measure/run.go \
    's = s.replace("if l.CPUPct > CPULimitPct {", "if false {")'

# --- уплотнение (server/store/metrics.go) ---

# M10: граница сырых значений сдвинута (48ч → 48 минут).
run "M10 граница сырых сдвинута" ./server/store/ "TestCompactRawTo5m" server/store/metrics.go \
    's = s.replace("MetricsRawKeep = 48 * time.Hour", "MetricsRawKeep = 48 * time.Minute")'

# M11: идемпотентность сломана (REPLACE → INSERT).
run "M11 идемпотентность сломана" ./server/store/ "TestCompactIdempotent" server/store/metrics.go \
    's = s.replace("OR REPLACE INTO ", "INTO ")'

# M12: p95 заменён максимумом.
run "M12 p95 = максимум" ./server/store/ "TestCompactP95" server/store/metrics.go \
    's = s.replace("P95: percentile(c.vals, 0.95),", "P95: maxOf(c.vals),")'

# --- SNMP (server/metrics) ---

# M13: переполнение счётчика не учитывается.
run "M13 переполнение счётчика снято" ./server/metrics/ "TestCounterDeltaWrap" server/metrics/snmp.go \
    's = s.replace("""	if cur < prev {
		return (counter32max - prev) + cur
	}""", "")'

# --- blob (server/agentapi) ---

# M14: предел blob снят.
run "M14 предел blob снят" ./server/agentapi/ "TestBlobLimits" server/agentapi/agentapi.go \
    's = s.replace("n > MaxBlobBytes", "n > MaxBlobBytes*1000")'

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
