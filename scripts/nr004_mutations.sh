#!/bin/bash
# NR-004: мутационное тестирование server/api и cmd/netatlas-server.
# Каждая мутация обязана уронить хотя бы один тест; после прогона
# файлы восстанавливаются побайтово.
set -u
export PATH=$HOME/tools/go/bin:$PATH
cd "$(dirname "$0")/.."
BAK=/tmp/nr004
mkdir -p $BAK
cp server/api/api.go $BAK/
cp cmd/netatlas-server/config.go $BAK/config.go

mutate_file() { # $1 = путь, $2 = python-код патча
    python3 - "$1" <<EOF
import sys
p = sys.argv[1]
s = open(p).read()
$2
open(p, "w").write(s)
EOF
}

check() { # $1 = имя мутации, $2 = go test -run
    if ! go test ./server/api/ ./cmd/netatlas-server/ -count=1 -run "$2" >/tmp/nr004_mut.log 2>&1; then
        echo "M($1): поймана — $2 красный"
    else
        echo "M($1): НЕ поймана — $2 зелёный!!!"
        FAIL=1
    fi
    cp $BAK/api.go server/api/api.go
    cp $BAK/config.go cmd/netatlas-server/config.go
}

FAIL=0

# M1: проверка токена снята (auth-мидлварь пропускает всех).
mutate_file server/api/api.go 's = s.replace("\t\tif !ok {\n\t\t\tw.Header().Set(\"WWW-Authenticate\", `Bearer realm=\"netatlas\"`)\n\t\t\twriteJSON(w, http.StatusUnauthorized, errorBody{\"требуется авторизация\"})\n\t\t\treturn\n\t\t}", "")'
check "M1 auth снят" "TestUnauthorized"

# M2: проверка Scope в verify снята (ping всем адресам).
mutate_file server/api/api.go 's = s.replace("\tfor _, ip := range info.IPs {\n\t\tif a.scope.Contains(ip) {\n\t\t\ttargets = append(targets, ip)\n\t\t}\n\t}\n\tif len(targets) == 0 {\n\t\twriteJSON(w, http.StatusBadRequest, errorBody{\"адреса устройства вне подсетей проверки: сеть не трогается\"})\n\t\treturn\n\t}", "\ttargets = info.IPs")'
check "M2 Scope снят" "TestVerifyOutOfScope"

# M3: DisallowUnknownFields снят.
mutate_file server/api/api.go 's = s.replace("\tdec.DisallowUnknownFields()", "\t_ = dec")'
check "M3 строгий JSON снят" "TestUnknownFieldRejected"

# M4: минимальная длина токена не проверяется.
mutate_file server/api/api.go 's = s.replace("\tif len(token) < MinTokenLen {\n\t\treturn nil, fmt.Errorf(\"api: токен короче %d символов\", MinTokenLen)\n\t}", "")'
mutate_file cmd/netatlas-server/config.go 's = s.replace("\tif len(cfg.token) < 24 {\n\t\treturn config{}, fmt.Errorf(\"%w: NETATLAS_TOKEN короче 24 символов\", errUsage)\n\t}", "")'
check "M4 длина токена снята" "TestShortTokenRejected"

# M5: ErrNotManual отвечает 500 вместо 409.
mutate_file server/api/api.go 's = s.replace("\tcase errors.Is(err, store.ErrNotManual):\n\t\twriteJSON(w, http.StatusConflict, errorBody{\"элемент не ручной: удаление запрещено\"})", "")'
check "M5 маппинг 409 снят" "TestDeleteDeviceCodes"

for f in api/api.go; do
    if ! cmp -s server/$f $BAK/$(basename $f); then
        echo "ОШИБКА: $f не восстановился"; exit 1
    fi
done
if ! cmp -s cmd/netatlas-server/config.go $BAK/config.go; then
    echo "ОШИБКА: config.go не восстановился"; exit 1
fi
if [ "$FAIL" -ne 0 ]; then
    echo "ИТОГ: ЕСТЬ ВЫЖИВШИЕ МУТАЦИИ"; exit 1
fi
echo "ИТОГ: все мутации пойманы, файлы восстановлены побайтово"
