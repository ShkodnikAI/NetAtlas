#!/bin/bash
# NR-024: мутационное тестирование server/agentapi, cmd/netatlas-server,
# server/store (агенты). Каждая мутация обязана уронить хотя бы один
# тест; после прогона файлы восстанавливаются побайтово.
set -u
export PATH=$HOME/tools/go/bin:$PATH
cd "$(dirname "$0")/.."

FAIL=0
RAN=0
declare -A BACKUPS

# Аргументы — фильтры по имени мутации (подстрока); без аргументов
# прогоняются все. Пример: bash scripts/nr024_mutations.sh M12 M14
ONLY=("$@")

backup() {
    if [ -z "${BACKUPS[$1]:-}" ]; then
        BAK="/tmp/nr024_$(echo "$1" | tr '/' '_').bak"
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
    if ! go test "$2" -count=1 -run "$3" >/tmp/nr024_mut.log 2>&1; then
        echo "M($1): поймана — $3 красный"
    else
        echo "M($1): НЕ поймана — $3 зелёный!!!"
        FAIL=1
    fi
    cp "${BACKUPS[$F]}" "$F"
}

# --- server/agentapi ---

# M1: обязательный клиентский сертификат снят.
run "M1 RequireAndVerifyClientCert снят" ./server/agentapi/ "TestNoClientCertRejected" server/agentapi/agentapi.go \
    's = s.replace("ClientAuth:            tls.RequireAndVerifyClientCert,", "ClientAuth:            tls.NoClientCert,")'

# M2: проверка отзыва по серийнику сертификата снята.
run "M2 отзыв серийника снят" ./server/agentapi/ "TestRevokedHandshakeRejected" server/agentapi/agentapi.go \
    's = s.replace("certs[leaf.SerialNumber.String()]", "len(certs) < 0")'

# M3: проверка отзыва по статусу агента на handshake снята.
run "M3 отзыв агента на handshake снят" ./server/agentapi/ "TestRevokedHandshakeRejected" server/agentapi/agentapi.go \
    's = s.replace("if id := leaf.Subject.CommonName; agents[id] {", "if id := leaf.Subject.CommonName; len(agents) < 0 {")'

# M4: MinVersion TLS 1.3 понижен.
run "M4 TLS13 -> TLS12" ./server/agentapi/ "TestTLS12Rejected" server/agentapi/agentapi.go \
    's = s.replace("MinVersion:            tls.VersionTLS13,", "MinVersion:            tls.VersionTLS12,")'

# M5: лимит частоты регистрации снят.
run "M5 лимит частоты снят" ./server/agentapi/ "TestEnrollRateLimit" server/agentapi/agentapi.go \
    's = s.replace("EnrollRatePerMinute = 10", "EnrollRatePerMinute = 1000000")'

# M6: лимит тела регистрации снят.
run "M6 лимит тела enroll снят" ./server/agentapi/ "TestEnrollBodyLimit" server/agentapi/agentapi.go \
    's = s.replace("MaxEnrollBody = 64 << 10", "MaxEnrollBody = 8 << 20")'

# M7: лимит тела инвентаря снят.
run "M7 лимит тела inventory снят" ./server/agentapi/ "TestInventoryLimits" server/agentapi/agentapi.go \
    's = s.replace("MaxInventoryBody = 2 << 20", "MaxInventoryBody = 64 << 20")'

# M8: расход одноразового токена снят.
run "M8 одноразовость токена снята" ./server/agentapi/ "TestEnrollTokenValidation" server/agentapi/agentapi.go \
    's = s.replace("""\tif err := a.st.ConsumeEnrollToken(r.Context(), req.Token); err != nil {
\t\tswitch {
\t\tcase errors.Is(err, store.ErrTokenUsed):
\t\t\ta.auditDeny(r.Context(), "agent_enroll", cn, "токен уже использован")
\t\t\twriteJSON(w, http.StatusConflict, errorBody{"токен уже использован"})
\t\tcase errors.Is(err, store.ErrTokenExpired):
\t\t\ta.auditDeny(r.Context(), "agent_enroll", cn, "срок токена истёк")
\t\t\twriteJSON(w, http.StatusUnauthorized, errorBody{"срок токена истёк"})
\t\tdefault:
\t\t\ta.auditDeny(r.Context(), "agent_enroll", cn, "токен не принят")
\t\t\twriteJSON(w, http.StatusUnauthorized, errorBody{"токен не принят"})
\t\t}
\t\treturn
\t}
""", "")'

# M9: строгий разбор JSON ослаблен (подмена полей проходит).
run "M9 DisallowUnknownFields снят" ./server/agentapi/ "TestEnrollSpoofedAgentID" server/agentapi/agentapi.go \
    's = s.replace("\tdec.DisallowUnknownFields()\n", "")'

# M10: свежая проверка отзыва на маршрутах снята (кэш handshake —
# единственная защита).
run "M10 свежая проверка статуса снята" ./server/agentapi/ "TestRevokedAgentFreshCheck403" server/agentapi/agentapi.go \
    's = s.replace("revoked, err := a.st.IsAgentRevoked(r.Context(), cn)", "revoked, err := false, error(nil)")'

# M11: префикс личности agent: в CSR не проверяется.
run "M11 префикс CN в CSR снят" ./server/agentapi/ "TestEnrollRejectsBadCSR" server/agentapi/agentapi.go \
    's = s.replace("""\tcn := csr.Subject.CommonName
\tif !strings.HasPrefix(cn, AgentIDPrefix) {
\t\treturn \"\", fmt.Errorf(\"CN %q вне схемы agent:\", cn)
\t}
""", "\tcn := csr.Subject.CommonName\n")'

# --- cmd/netatlas-server ---

# M12: агентский слушатель включён по умолчанию.
run "M12 agent-listen включён по умолчанию" ./cmd/netatlas-server/ "TestParseConfigAgentsOffByDefault" cmd/netatlas-server/config.go \
    's = s.replace("""fs.StringVar(&cfg.agentListen, "agent-listen", "",
\t\t"адрес mTLS-слушателя агентов (по умолчанию выключен)")""", """fs.StringVar(&cfg.agentListen, "agent-listen", "127.0.0.1:8485",
\t\t"адрес mTLS-слушателя агентов")""")'

# M13: запрет совпадения портов снят.
run "M13 запрет совпадения портов снят" ./cmd/netatlas-server/ "TestParseConfigRejectsAgentPortClash" cmd/netatlas-server/config.go \
    's = s.replace("""\t\tif cfg.agentListen == cfg.listen || cfg.agentEnrollListen == cfg.listen {
\t\t\treturn config{}, fmt.Errorf("%w: порт агентов не смешивается с портом владельца", errUsage)
\t\t}
""", "")'

# --- server/store ---

# M14: отзыв агента не меняет статус.
run "M14 статус отзыва не пишется" ./server/store/ "TestRevokeAgentStates" server/store/agents.go \
    's = s.replace("UPDATE agents SET status = '"'"'revoked'"'"' WHERE id = ?", "UPDATE agents SET status = '"'"'active'"'"' WHERE id = ?")'

# M15: привязка MAC не ставит класс managed.
run "M15 класс managed не ставится" ./server/store/ "TestLinkAgentMACs" server/store/agents.go \
    "s = s.replace(\"VALUES (?, 'device', 'managed', '', '', '', '', 0, 0, ?, ?)\", \"VALUES (?, 'device', 'known_no_agent', '', '', '', '', 0, 0, ?, ?)\")"

# Контроль: файлы восстановлены побайтово, всё зелёное.
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
