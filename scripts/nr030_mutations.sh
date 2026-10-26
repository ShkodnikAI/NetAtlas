#!/bin/bash
# NR-030: мутационное тестирование новых источников данных конвейера
# (scanner/pipeline) и заполнения списка устройств (server/store).
# Каждая мутация обязана уронить хотя бы один тест; после прогона
# файлы восстанавливаются и проверяются побайтово.
set -u
export PATH=$HOME/tools/go/bin:$PATH
cd "$(dirname "$0")/.."

F1=scanner/pipeline/pipeline.go
F2=scanner/pipeline/merge.go
F3=scanner/pipeline/dns.go
F4=scanner/pipeline/local.go
F5=server/store/graph.go
BAK=/tmp/nr030_bak
mkdir -p $BAK
cp "$F1" "$F2" "$F3" "$F4" "$F5" "$BAK/"

mutate() { # $1 = файл, $2 = python-код патча
    python3 - "$1" <<EOF
import sys
p = sys.argv[1]
s = open(p).read()
$2
open(p, "w").write(s)
EOF
}

check() { # $1 = имя мутации, $2 = пакет, $3 = падающий тест
    if ! go test "$2" -count=1 -run "$3" >/tmp/nr030_mut.log 2>&1; then
        echo "M($1): поймана — $3 красный"
    else
        echo "M($1): НЕ поймана — $3 зелёный!!!"
        FAIL=1
    fi
    cp "$BAK/pipeline.go" "$F1"; cp "$BAK/merge.go" "$F2"
    cp "$BAK/dns.go" "$F3"; cp "$BAK/local.go" "$F4"; cp "$BAK/graph.go" "$F5"
}

FAIL=0

# M1: повторное чтение ARP снято (конвейер читает таблицу один раз).
mutate "$F1" 's = s.replace("\tif cfg.Ping {\n\t\tif again, aerr := deps.ReadARP(ctx); aerr == nil {", "\tif cfg.Ping {\n\t\tif again, aerr := deps.ReadARP(ctx); aerr == nil && len(again) < 0 {")'
check "M1 повтор ARP снят" ./scanner/pipeline/ "TestPipelineARPAgainAfterPing"

# M2: вливание хостов снято (хосты не становятся устройствами).
mutate "$F2" 's = s.replace("\tkept := hosts[:0]", "\tkept := hosts")'
check "M2 вливание хостов снято" ./scanner/pipeline/ "TestMergeDevicesUnit"

# M3: сортировка устройств снята (порядок зависит от входа).
mutate "$F2" 's = s.replace("\tsortByFirstIP(devices)", "\t_ = devices")'
check "M3 порядок снят" ./scanner/pipeline/ "TestMergeDevicesUnit"

# M4: проверка границ в reverseDNS снята (запросы вне scope).
mutate "$F3" 's = s.replace("\t\tif scope == nil || !scope.Contains(ip) {", "\t\tif false {")'
check "M4 границы DNS сняты" ./scanner/pipeline/ "TestReverseDNSUnit"

# M5: ошибка резолвера роняет скан (вместо пропуска адреса).
mutate "$F3" 's = s.replace("\t\tif err != nil || len(names) == 0 {\n\t\t\treturn \"\", false, nil", "\t\tif err != nil {\n\t\t\treturn \"\", false, err\n\t\t}\n\t\tif len(names) == 0 {\n\t\t\treturn \"\", false, nil")'
check "M5 ошибка резолвера фатальна" ./scanner/pipeline/ "TestReverseDNSUnit"

# M6: локальные интерфейсы берут адреса вне границ.
mutate "$F4" 's = s.replace("\t\t\tif scope != nil && scope.Contains(a) && !containsAddr(d.IPs, a) {", "\t\t\tif !containsAddr(d.IPs, a) {")'
check "M6 границы интерфейсов сняты" ./scanner/pipeline/ "TestPipelineLocalInterfaces"

# M7: флаг NoDNS инвертирован (no_dns включает DNS).
mutate "$F1" 's = s.replace("\tif !cfg.NoDNS {", "\tif cfg.NoDNS {")'
check "M7 NoDNS инвертирован" ./scanner/pipeline/ "TestPipelineNoDNSOff"

# M8: список устройств без адресов (выборка device_ips не читается).
mutate "$F5" 's = s.replace("\t\tout[i].IPs = append(out[i].IPs, a)", "\t\t_ = i")'
check "M8 адреса в списке сняты" ./server/store/ "TestListDevicesFillsSlices"

# M9: имена в списке не заполняются.
mutate "$F5" 's = s.replace("\t\tout[i].Names = append(out[i].Names, model.Name{Source: source, Name: name, Seen: seenAt})", "\t\t_ = i")'
check "M9 имена в списке сняты" ./server/store/ "TestListDevicesFillsSlices"

# M10: наблюдения в списке не заполняются.
mutate "$F5" 's = s.replace("\t\tout[i].Observations = append(out[i].Observations, model.Observation{Source: source, Seen: seenAt})", "\t\t_ = i")'
check "M10 наблюдения в списке сняты" ./server/store/ "TestListDevicesFillsSlices"

if ! cmp -s "$F1" "$BAK/pipeline.go" || ! cmp -s "$F2" "$BAK/merge.go" || \
   ! cmp -s "$F3" "$BAK/dns.go" || ! cmp -s "$F4" "$BAK/local.go" || \
   ! cmp -s "$F5" "$BAK/graph.go"; then
    echo "ОШИБКА: файлы не восстановились"; exit 1
fi
if [ "$FAIL" -ne 0 ]; then
    echo "ИТОГ: ЕСТЬ ВЫЖИВШИЕ МУТАЦИИ"; exit 1
fi
echo "ИТОГ: все мутации пойманы, файлы восстановлены побайтово"
