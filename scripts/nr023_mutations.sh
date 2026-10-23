#!/bin/bash
# NR-023: мутационное тестирование хвостов волны 1 (server/store/scan.go,
# scanner/scan.go, server/api/scan.go, scanner/dhcp/dhcp.go). Каждая
# мутация обязана уронить хотя бы один тест; после прогона файлы
# восстанавливаются и проверяются побайтово.
set -u
export PATH=$HOME/tools/go/bin:$PATH
cd "$(dirname "$0")/.."

FAIL=0
declare -A BACKUPS

backup() { # $1 = файл
    if [ -z "${BACKUPS[$1]:-}" ]; then
        BAK="/tmp/nr023_$(echo "$1" | tr '/' '_').bak"
        cp "$1" "$BAK"
        BACKUPS[$1]="$BAK"
    fi
}

mutate_file() { # $1 = файл, $2 = python-код патча
    python3 - "$1" <<EOF
import sys
p = sys.argv[1]
s = open(p).read()
$2
open(p, "w").write(s)
EOF
}

run() { # $1 = имя, $2 = пакет, $3 = тест, $4 = файл, $5 = патч
    F="$4"
    backup "$F"
    mutate_file "$F" "$5"
    if ! go test "$2" -count=1 -run "$3" >/tmp/nr023_mut.log 2>&1; then
        echo "M($1): поймана — $3 красный"
    else
        echo "M($1): НЕ поймана — $3 зелёный!!!"
        FAIL=1
    fi
    cp "${BACKUPS[$F]}" "$F"
}

# M1: удаление устаревшей ip:-записи снято (dropIPHost не вызывается
# для адресов устройств скана).
run "M1 дедуп ip-хостов снят" ./server/store/ "TestSaveScanIPHostDedupOnMAC" server/store/scan.go \
    's = s.replace("""\tfor ip := range scanIPs {
\t\tif err := dropIPHost(ctx, tx, ip, actor); err != nil {
\t\t\treturn err
\t\t}
\t}""", "\t_ = scanIPs")'

# M2: сохранение хостов без MAC снято (вверх по циклу).
run "M2 сохранение ip-хостов снято" ./server/store/ "TestSaveScanIPHostSaved" server/store/scan.go \
    's = s.replace("""\tfor _, h := range scan.Hosts {
\t\tkey := h.IP.String()""", """\tfor _, h := range scan.Hosts {
\t\t_ = h
\t\tcontinue
\t\tkey := h.IP.String()""")'

# M3: SSDP-фильтр гостей снят.
run "M3 SSDP-скип снят" ./scanner/ "TestSSDPSkippedForGuestIPs" scanner/scan.go \
    's = s.replace("""\t\tif skipSSDP != nil && skipSSDP[ip.String()] {
\t\t\tcontinue // гость или «известный без агента»: имя не сохраняется
\t\t}""", "")'

# M4: пары leases_path/leases_format не проверяются (проверка только пути).
run "M4 связка полей аренд снята" ./server/api/ "TestScanLeasesValidation" server/api/scan.go \
    's = s.replace("""\tif path == \"\" || format == \"\" {
\t\treturn nil, fmt.Errorf(\"leases_path и leases_format указываются вместе\")
\t}""", """\tif path == \"\" {
\t\treturn nil, fmt.Errorf(\"leases_path и leases_format указываются вместе\")
\t}""")'

# M5: лимит 5 МБ — защита двухслойная (пред-проверка обработчика и
# сам парсер dhcp с собственным тестом лимита); снимаются оба слоя.
backup server/api/scan.go
backup scanner/dhcp/dhcp.go
mutate_file server/api/scan.go 's = s.replace("""\tif len(data) > dhcp.MaxInputSize {""", """\tif false {""")'
mutate_file scanner/dhcp/dhcp.go 's = s.replace("""\tif len(data) > MaxInputSize {""", """\tif false {""")'
if ! go test ./server/api/ -count=1 -run TestScanLeasesValidation >/tmp/nr023_mut.log 2>&1; then
    echo "M(M5 лимит 5МБ снят, оба слоя): поймана — TestScanLeasesValidation красный"
else
    echo "M(M5 лимит 5МБ снят, оба слоя): НЕ поймана!!!"
    FAIL=1
fi
cp "${BACKUPS[server/api/scan.go]}" server/api/scan.go
cp "${BACKUPS[scanner/dhcp/dhcp.go]}" scanner/dhcp/dhcp.go

# M6: verify-эндпоинт всегда отвечает ok:true.
run "M6 verify всегда ok" ./server/api/ "TestAuditVerifyEndpoint" server/api/api.go \
    's = s.replace("""\tif err := audit.Verify(r.Context(), a.store.DB()); err != nil {""", """\tif false {
\t\t_ = audit.Verify(r.Context(), a.store.DB())
\t\t_ = r
\t}
\tif err := error(nil); err != nil {""")'

# M7: runScan не передаёт Hosts в SaveScan (хосты теряются).
run "M7 Hosts теряются в runScan" ./server/api/ "TestScanSavesHostsWithoutMAC" server/api/scan.go \
    's = s.replace("""\t\tDevices:  res.Devices,
\t\tHosts:    res.Hosts,""", """\t\tDevices:  res.Devices,""")'

for F in "${!BACKUPS[@]}"; do
    if ! cmp -s "$F" "${BACKUPS[$F]}"; then
        echo "ОШИБКА: $F не восстановился"; exit 1
    fi
done
if [ "$FAIL" -ne 0 ]; then
    echo "ИТОГ: ЕСТЬ ВЫЖИВШИЕ МУТАЦИИ"; exit 1
fi
echo "ИТОГ: все мутации пойманы, файлы восстановлены побайтово"
