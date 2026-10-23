#!/bin/bash
# NR-021: мутационное тестирование scanner/topology/build.go.
# Каждая мутация обязана уронить хотя бы один тест; после прогона файл
# восстанавливается и проверяется побайтово.
set -u
export PATH=$HOME/tools/go/bin:$PATH
cd "$(dirname "$0")/.."
F=scanner/topology/build.go
BAK=/tmp/nr021_build.go.bak
cp "$F" "$BAK"

mutate() { # $1 = python-код патча
    python3 - "$F" <<EOF
import sys
p = sys.argv[1]
s = open(p).read()
$1
open(p, "w").write(s)
EOF
}

check() { # $1 = имя мутации, $2 = ожидаемый падающий тест
    if ! go test ./scanner/topology/ -count=1 -run "$2" >/tmp/nr021_mut.log 2>&1; then
        echo "M($1): поймана — $2 красный"
    else
        echo "M($1): НЕ поймана — $2 зелёный!!!"
        FAIL=1
    fi
    cp "$BAK" "$F"
}

FAIL=0

# M1: предсбор MAC коммутаторов снят (тело collectSwitchMACs пустое).
mutate 's = s.replace("\t\tif devID, ok := b.ipToDevice[r.Target.String()]; ok {\n\t\t\tb.switchMACs[devID] = true\n\t\t}", "\t\t_ = r")'
check "M1 предсбор MAC снят" "TestNR021SwitchMACKnownBeforeFDB"

# M2: выбор ближайшего порта снят (все MAC порта считаются своими).
mutate 's = s.replace("if p := nearest[mac]; p.swID == swID && p.port == port {", "if true {")'
check "M2 ближайший порт снят" "TestNR021NearestPort"

# M3: transitLink снят (нет inferred-связи для портов без своих MAC).
mutate 's = s.replace("func (b *builder) transitLink(swID, port string, macs []string, nearest map[string]place) {\n\ttarget := \"\"", "func (b *builder) transitLink(swID, port string, macs []string, nearest map[string]place) {\n\ttarget := \"\"\n\tif true {\n\t\treturn\n\t}")'
check "M3 transitLink снят" "TestNR021NearestPort"

if ! cmp -s "$F" "$BAK"; then
    echo "ОШИБКА: build.go не восстановился"; exit 1
fi
if [ "$FAIL" -ne 0 ]; then
    echo "ИТОГ: ЕСТЬ ВЫЖИВШИЕ МУТАЦИИ"; exit 1
fi
echo "ИТОГ: все мутации пойманы, build.go восстановлен побайтово"
