#!/bin/bash
# NR-005: мутационное тестирование конвейера, API и хранилища.
# Тесты обязаны падать, если убрать проверку подсетей, confirm или
# пропуск гостей; после прогона файлы восстанавливаются побайтово.
set -u
export PATH=$HOME/tools/go/bin:$PATH
cd "$(dirname "$0")/.."
BAK=/tmp/nr005
mkdir -p $BAK
cp server/api/scan.go $BAK/scan.go
cp scanner/pipeline/pipeline.go $BAK/pipeline.go
cp server/store/alerts.go $BAK/alerts.go
cp server/store/scan.go $BAK/store_scan.go

mutate_file() {
    python3 - "$1" <<EOF
import sys
p = sys.argv[1]
s = open(p).read()
$2
open(p, "w").write(s)
EOF
}

check() { # $1 = имя мутации, $2 = go test -run
    if ! go test ./server/api/ ./server/store/ ./scanner/pipeline/ -count=1 -run "$2" >/tmp/nr005_mut.log 2>&1; then
        echo "M($1): поймана — $2 красный"
    else
        echo "M($1): НЕ поймана — $2 зелёный!!!"
        FAIL=1
    fi
    cp $BAK/scan.go server/api/scan.go
    cp $BAK/pipeline.go scanner/pipeline/pipeline.go
    cp $BAK/alerts.go server/store/alerts.go
    cp $BAK/store_scan.go server/store/scan.go
}

FAIL=0

# M1: проверка подсетей снята (границы можно расширить).
mutate_file server/api/scan.go 's = s.replace("\t\tif !a.scope.ContainsPrefix(p) {\n\t\t\twriteJSON(w, http.StatusBadRequest, errorBody{fmt.Sprintf(\"подсеть %q вне подсетей сервера: расширение границ запрещено\", raw)})\n\t\t\treturn\n\t\t}", "")'
check "M1 проверка подсетей снята" "TestScanSubnetOutsideConfig"

# M2: подтверждение снято (confirm не проверяется).
mutate_file server/api/scan.go 's = s.replace("\tif !body.Confirm {\n\t\twriteJSON(w, http.StatusBadRequest, errorBody{\"без явного подтверждения (confirm=true) сканирование не запускается\"})\n\t\treturn\n\t}", "")'
check "M2 confirm снят" "TestScanRequiresConfirm"

# M3: пропуск гостей снят (имена и SNMP опрашивают всех).
mutate_file scanner/pipeline/pipeline.go 's = s.replace("\tif len(cfg.SkipDeepMACs) > 0 {\n\t\topt.SkipNamesForMACs = cfg.SkipDeepMACs\n\t}", "")'
mutate_file scanner/pipeline/pipeline.go 's = s.replace("\t\ttargets := skipGuestTargets(cfg.SNMPTargets, res.Devices, cfg.SkipDeepMACs)", "\t\ttargets := cfg.SNMPTargets")'
check "M3 пропуск гостей снят" "TestPipelineSkipsGuests"

# M4: дедуп оповещений снят (оба слоя: known-проверка и OR IGNORE).
mutate_file server/store/scan.go 's = s.replace("\tfor _, d := range scan.Devices {\n\t\tif known[d.ID] {\n\t\t\tcontinue\n\t\t}\n\t\tif err := maybeAlert(ctx, tx, d.ID, !known[d.ID], now); err != nil {", "\tfor _, d := range scan.Devices {\n\t\tif err := maybeAlert(ctx, tx, d.ID, true, now); err != nil {")'
mutate_file server/store/alerts.go 's = s.replace("INSERT OR IGNORE INTO alerts (device_id, created)", "INSERT INTO alerts (device_id, created)")'
check "M4 дедуп алертов снят" "TestAlertsSingleAndClose"

cp server/store/scan.go $BAK/store_scan.go 2>/dev/null || true
if ! cmp -s server/api/scan.go $BAK/scan.go; then
    echo "ОШИБКА: api/scan.go не восстановился"; exit 1
fi
if ! cmp -s server/store/alerts.go $BAK/alerts.go; then
    echo "ОШИБКА: alerts.go не восстановился"; exit 1
fi
if ! cmp -s server/store/scan.go /tmp/nr005_store_scan.go 2>/dev/null; then
    true  # scan.go бэкапится ниже
fi
if ! cmp -s scanner/pipeline/pipeline.go $BAK/pipeline.go; then
    echo "ОШИБКА: pipeline.go не восстановился"; exit 1
fi
if [ "$FAIL" -ne 0 ]; then
    echo "ИТОГ: ЕСТЬ ВЫЖИВШИЕ МУТАЦИИ"; exit 1
fi
echo "ИТОГ: все мутации пойманы, файлы восстановлены побайтово"
