#!/bin/bash
# NR-006: мутационное тестирование agent/spool, agent (ядро),
# agent/collect. Каждая мутация обязана уронить хотя бы один тест;
# после прогона файлы восстанавливаются побайтово.
set -u
export PATH=$HOME/tools/go/bin:$PATH
cd "$(dirname "$0")/.."

FAIL=0
RAN=0
declare -A BACKUPS

# Аргументы — фильтры по имени мутации (подстрока).
ONLY=("$@")

backup() {
    if [ -z "${BACKUPS[$1]:-}" ]; then
        BAK="/tmp/nr006_$(echo "$1" | tr '/' '_').bak"
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
    if ! go test "$2" -count=1 -run "$3" >/tmp/nr006_mut.log 2>&1; then
        echo "M($1): поймана — $3 красный"
    else
        echo "M($1): НЕ поймана — $3 зелёный!!!"
        FAIL=1
    fi
    cp "${BACKUPS[$F]}" "$F"
}

# --- agent/spool ---

# M1: вытеснение по лимиту снято — очередь растёт без ограничений.
run "M1 лимит очереди снят" ./agent/spool/ "TestSpoolEvictsOldestWithinLimit" agent/spool/spool.go \
    's = s.replace("\ts.evictLocked()\n\treturn nil", "\treturn nil")'

# M10: порядок очереди сломан (отдаётся самое свежее).
run "M10 порядок очереди сломан" ./agent/spool/ "TestSpoolFIFOAndAck" agent/spool/spool.go \
    's = s.replace("id = names[0]", "id = names[len(names)-1]")'

# M7: в коде агента появилось упоминание слушающего сокета.
run "M7 упоминание listener" ./agent/ "TestAgentSourceOpensNoListeners" agent/spool/spool.go \
    's = s + "\nvar _ = \"net.Listen(\"\n"'

# --- agent (ядро) ---

# M2: рост паузы снят — пауза всегда базовая.
run "M2 рост паузы снят" ./agent/ "TestRunBackoffExponential" agent/agent.go \
    's = s.replace("grown := base << fails", "grown := base")'

# M3: проверка цепочки сервера снята — чужой CA принимается.
run "M3 проверка CA снята" ./agent/ "TestEnrollForeignCARejected" agent/client.go \
    's = s.replace("""		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("agent: сертификат сервера: %w", err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
			return fmt.Errorf("agent: сервер не от нашего CA: %w", err)
		}
		return nil""", """		_, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("agent: сертификат сервера: %w", err)
		}
		_ = pool
		return nil""")'

# M4: токен регистрации сохраняется на диск.
run "M4 токен сохранён" ./agent/ "TestEnrollAndCheckin" agent/client.go \
    's = s.replace("""	if err := writePublic(filepath.Join(dir, certFile), []byte(out.CertPEM)); err != nil {
		return "", err
	}
	return out.AgentID, nil""", """	if err := writePublic(filepath.Join(dir, certFile), []byte(out.CertPEM)); err != nil {
		return "", err
	}
	_ = os.WriteFile(filepath.Join(dir, "last-token.txt"), []byte(token), 0o600)
	return out.AgentID, nil""")'

# M8: версия схемы в конверте отправления потеряна.
run "M8 schema_ver конверта обнулён" ./agent/ "TestRunOnceSendAndSpool" agent/agent.go \
    's = s.replace("SchemaVer:   collect.SchemaVersion,", "SchemaVer:   0,")'

# M9: интервал опроса от сервера игнорируется.
run "M9 интервал из checkin игнорируется" ./agent/ "TestRunOnceSendAndSpool" agent/agent.go \
    's = s.replace("if check.PollSec > 0 {", "if false {")'

# --- agent/collect ---

# M5: версия схемы отчёта изменена.
run "M5 версия схемы изменена" ./agent/collect/ "TestBuildReportToleratesErrors" agent/collect/schema.go \
    's = s.replace("const SchemaVersion = 1", "const SchemaVersion = 2")'

# M6: ошибки сборщиков не фиксируются в отчёте.
run "M6 collector_errors потеряны" ./agent/collect/ "TestBuildReportToleratesErrors" agent/collect/collectors.go \
    's = s.replace("rep.CollectorErrors = append(rep.CollectorErrors, c.Name()+\": \"+err.Error())", "_ = c")'

# M11: проверка имени сценария снята (текст из сети в команду).
run "M11 проверка имени сценария снята" ./agent/collect/ "TestPowerShellRunnerRejectsBadScriptName" agent/collect/powershell.go \
    's = s.replace("if strings.ContainsAny(script,", "if false && strings.ContainsAny(script,")'

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
