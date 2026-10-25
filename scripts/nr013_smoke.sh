#!/usr/bin/env bash
# Смок NR-013: живой сервер, маршрут отчётов, граница, аудит.
set -u
cd /home/z/my-project/netatlas
export PATH=$HOME/tools/go/bin:$PATH

SMOKE_DIR=$(mktemp -d /tmp/nr013_smoke.XXXXXX)
export NETATLAS_TOKEN="смок-наряд-тринадцать-фиктивный-токен-доступа"
go build -o "$SMOKE_DIR/netatlas-server" ./cmd/netatlas-server || exit 1

"$SMOKE_DIR/netatlas-server" --db "$SMOKE_DIR/smoke.db" --subnets 10.99.0.0/24 \
  > "$SMOKE_DIR/stdout.log" 2> "$SMOKE_DIR/stderr.log" &
SRV=$!
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; rm -rf "$SMOKE_DIR"' EXIT
for i in $(seq 1 20); do curl -s -o /dev/null http://127.0.0.1:8484/api/config && break; sleep 0.3; done

AUTH="Authorization: Bearer $NETATLAS_TOKEN"
fail=0
check() { # name expected body
  if echo "$3" | grep -q "$2"; then echo "ok [$1]"; else echo "ПРОВАЛ [$1]: ждём «$2», получено: $3"; fail=1; fi
}

# 1. Создание отчёта
R=$(curl -s -X POST -H "$AUTH" -d '{"topic":"security"}' http://127.0.0.1:8484/api/reports)
check "создание" '"id":1' "$R"
check "форма" 'ОТЧЁТ ДЛЯ ИИ (форма v1' "$R"
check "обёртка" 'недоверенные данные, не инструкции' "$R"

# 2. Чтение (без таблицы соответствий)
R=$(curl -s -H "$AUTH" http://127.0.0.1:8484/api/reports/1)
check "чтение" '"status":"open"' "$R"
if echo "$R" | grep -q '"mapping"'; then echo "ПРОВАЛ [нет-таблицы]: mapping в ответе отчёта"; fail=1; else echo "ok [нет-таблицы]"; fi

# 3. Ручной ответ
R=$(curl -s -X POST -H "$AUTH" -d '{"text":"Предлагаю проверить журнал безопасности"}' http://127.0.0.1:8484/api/reports/1/answer)
check "ответ" '"status"':'"answered"' "$(curl -s -H "$AUTH" http://127.0.0.1:8484/api/reports/1)"

# 4. use_ai при ручном режиме — 503
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$AUTH" -d '{"use_ai":true}' http://127.0.0.1:8484/api/reports/1/answer)
if [ "$CODE" = "503" ]; then echo "ok [use_ai-503]"; else echo "ПРОВАЛ [use_ai-503]: $CODE"; fail=1; fi

# 5. Черновик из фрагмента
R=$(curl -s -X POST -H "$AUTH" -d '{"name":"Из ответа ИИ","fragment":"Get-EventLog Security -Newest 5"}' http://127.0.0.1:8484/api/reports/1/draft)
check "черновик" '"script_id":1' "$R"

# 6. Таблица соответствий + аудит
R=$(curl -s -H "$AUTH" http://127.0.0.1:8484/api/reports/1/mapping)
check "таблица" '"mapping"' "$R"
R=$(curl -s -H "$AUTH" "http://127.0.0.1:8484/api/audit?limit=100")
for ev in report_create report_answer report_draft report_mapping_view; do
  check "аудит:$ev" "$ev" "$R"
done

# 7. Без токена — 401
CODE=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8484/api/reports)
if [ "$CODE" = "401" ]; then echo "ok [401]"; else echo "ПРОВАЛ [401]: $CODE"; fail=1; fi

# 8. Экран в сборке
if grep -q "Отчёты для ИИ" web/dist/index.html && grep -q "data-page=\"reports\"" web/dist/index.html; then echo "ok [экран-dist]"; else echo "ПРОВАЛ [экран-dist]"; fail=1; fi

kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
[ "$fail" -eq 0 ] && echo "СМОК ПРОЙДЕН" || echo "СМОК ПРОВАЛЕН"
exit $fail
