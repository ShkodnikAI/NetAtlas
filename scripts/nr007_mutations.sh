#!/bin/bash
# NR-007: мутационное тестирование agent/verify, pki, server/store
# (токены). Каждая мутация обязана уронить хотя бы один тест; после
# прогона файлы восстанавливаются побайтово.
set -u
export PATH=$HOME/tools/go/bin:$PATH
cd "$(dirname "$0")/.."

FAIL=0
declare -A BACKUPS

backup() {
    if [ -z "${BACKUPS[$1]:-}" ]; then
        BAK="/tmp/nr007_$(echo "$1" | tr '/' '_').bak"
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
    if ! go test "$2" -count=1 -run "$3" >/tmp/nr007_mut.log 2>&1; then
        echo "M($1): поймана — $3 красный"
    else
        echo "M($1): НЕ поймана — $3 зелёный!!!"
        FAIL=1
    fi
    cp "${BACKUPS[$F]}" "$F"
}

# M1: проверка цели снята.
run "M1 проверка цели снята" ./agent/verify/ "TestVerifyTargetChanged" agent/verify/verify.go \
    's = s.replace("""\tif sj.Envelope.AgentID != selfID {
\t\treturn ErrWrongTarget
\t}""", "")'

# M2: проверка просрочки снята.
run "M2 просрочка снята" ./agent/verify/ "TestVerifyExpired" agent/verify/verify.go \
    's = s.replace("""\tif now.After(sj.Envelope.ExpiresAt.Add(ClockSkew)) {
\t\treturn ErrExpired
\t}""", "")'

# M3: проверка «ещё не действует» снята.
run "M3 issued_at снят" ./agent/verify/ "TestVerifyNotYetValid" agent/verify/verify.go \
    's = s.replace("""\tif now.Add(ClockSkew).Before(sj.Envelope.IssuedAt) {
\t\treturn ErrNotYetValid
\t}""", "")'

# M4: проверка повтора снята.
run "M4 повтор снят" ./agent/verify/ "TestVerifyReplaySameJobID" agent/verify/verify.go \
    's = s.replace("""\t\tif hit {
\t\t\treturn ErrReplay
\t\t}""", "")'

# M5: проверка отзыва снята.
run "M5 отзыв снят" ./pki/ "TestVerifyPeerRevoked" pki/pki.go \
    's = s.replace("""\tfor _, serial := range revoked {
\t\tif cert.SerialNumber.String() == serial {
\t\t\treturn fmt.Errorf(\"pki: сертификат %s отозван\", cert.SerialNumber)
\t\t}
\t}""", "\t_ = revoked")'

# M6: проверка хэша содержимого снята.
run "M6 хэш содержимого снят" ./agent/verify/ "TestVerifyContentTampered" agent/verify/verify.go \
    's = s.replace("""\tif len(sj.Content) > 0 {
\t\tif !equalBytes(signing.HashContent(sj.Content), sj.Envelope.ContentSHA256) {
\t\t\treturn ErrContent
\t\t}
\t}""", "\t_ = sj")'

# M7: проверка отсутствия подписи снята (пустая подпись уходит в
# ed25519.Verify).
run "M7 нет подписи снят" ./agent/verify/ "TestVerifyNoSignature" agent/verify/verify.go \
    's = s.replace("""\tif len(sj.Signature) == 0 {
\t\treturn ErrNoSignature
\t}""", "")'

# M8: одноразовость токена снята.
run "M8 одноразовость токена снята" ./server/store/ "TestEnrollTokenLifecycle" server/store/pki.go \
    's = s.replace("""\tif usedAt != \"\" {
\t\treturn ErrTokenUsed
\t}""", "")'

# M9: срок токена снят.
run "M9 срок токена снят" ./server/store/ "TestEnrollTokenExpired" server/store/pki.go \
    's = s.replace("""\tif time.Now().After(exp) {
\t\treturn ErrTokenExpired
\t}""", "\t_ = exp")'

# M10: проверка прав ключа снята.
run "M10 права ключа сняты" ./pki/ "TestKeyPermsEnforced" pki/pki.go \
    's = s.replace("""\tif perm := fi.Mode().Perm(); perm != 0o600 {""", """\tif false {""")'

# M11: проверка подписи CSR снята.
run "M11 CheckSignature CSR снят" ./pki/ "TestSignAgentCSRRejectsTamperedSignature" pki/pki.go \
    's = s.replace("""\tif err := csr.CheckSignature(); err != nil {
\t\treturn nil, fmt.Errorf("pki: CSR агента: подпись запроса не сходится: %w", err)
\t}""", "\t_ = csr")'

for F in "${!BACKUPS[@]}"; do
    if ! cmp -s "$F" "${BACKUPS[$F]}"; then
        echo "ОШИБКА: $F не восстановился"; exit 1
    fi
done
if [ "$FAIL" -ne 0 ]; then
    echo "ИТОГ: ЕСТЬ ВЫЖИВШИЕ МУТАЦИИ"; exit 1
fi
echo "ИТОГ: все мутации пойманы, файлы восстановлены побайтово"
