#!/bin/bash
# NR-003: мутационное тестирование server/store и server/audit.
# Каждая мутация обязана уронить хотя бы один тест; после прогона
# файлы восстанавливаются побайтово.
set -u
export PATH=$HOME/tools/go/bin:$PATH
cd "$(dirname "$0")/.."
BAK=/tmp/nr003
mkdir -p $BAK
cp server/store/migrations/0001_init.sql server/store/migrations/0002_audit_no_update.sql server/store/migrations/0003_audit_no_delete.sql $BAK/
cp server/store/scan.go server/store/backup.go server/store/manual.go server/audit/audit.go $BAK/

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
    if ! go test ./server/... -count=1 -run "$2" >/tmp/nr003_mut.log 2>&1; then
        echo "M($1): поймана — $2 красный"
    else
        echo "M($1): НЕ поймана — $2 зелёный!!!"
        FAIL=1
    fi
    cp $BAK/* server/store/ 2>/dev/null
    cp $BAK/audit.go server/audit/
    cp $BAK/0001_init.sql $BAK/0002_audit_no_update.sql $BAK/0003_audit_no_delete.sql server/store/migrations/
}

FAIL=0

# M1: триггеры append-only сняты (миграции 2 и 3 пустые).
mutate_file server/store/migrations/0002_audit_no_update.sql 's = ""'
mutate_file server/store/migrations/0003_audit_no_delete.sql 's = ""'
check "M1 триггеры сняты" "TestAuditAppendOnly|TestAuditVerifyCatchesTamper"

# M2: Verify не проверяет цепочку (всегда nil).
mutate_file server/audit/audit.go 's = s.replace("\t\tn++\n", "\t\tn++\n\t\t_ = e\n\t\tcontinue\n")'
check "M2 Verify слепой" "TestAuditVerifyCatchesTamper"

# M3: SaveScan затирает ручные поля (class берётся из excluded).
mutate_file server/store/scan.go 's = s.replace("ON CONFLICT(id) DO UPDATE SET\n\t\t\tkind = excluded.kind,", "ON CONFLICT(id) DO UPDATE SET\n\t\t\tkind = excluded.kind,\n\t\t\tclass = excluded.class,")'
check "M3 class затирается" "TestSaveScanTwicePreservesManualFields"

# M4: Backup перезаписывает существующий файл.
mutate_file server/store/backup.go 's = s.replace("\tif _, err := os.Stat(path); err == nil {\n\t\treturn fmt.Errorf(\"store: %w: %s\", ErrBackupExists, path)\n\t} else if !errors.Is(err, os.ErrNotExist) {\n\t\treturn fmt.Errorf(\"store: путь копии %s: %w\", path, err)\n\t}\n", "")'
check "M4 Backup перезаписывает" "TestBackupCreatesAndRefusesOverwrite"

# M5: удаление найденного сканером устройства разрешено.
mutate_file server/store/manual.go 's = s.replace("\tif manual == 0 {\n\t\treturn fmt.Errorf(\"store: устройство %s: %w\", id, ErrNotManual)\n\t}", "")'
check "M5 удаление найденного разрешено" "TestDeleteManualOnly"

if ! cmp -s server/audit/audit.go $BAK/audit.go; then
    echo "ОШИБКА: audit.go не восстановился"; exit 1
fi
for f in scan.go backup.go manual.go 0001_init.sql 0002_audit_no_update.sql 0003_audit_no_delete.sql; do
    SRC=server/store/$f
    [ -f $SRC ] || SRC=server/store/migrations/$f
    if ! cmp -s "$SRC" "$BAK/$f"; then
        echo "ОШИБКА: $f не восстановился"; exit 1
    fi
done
if [ "$FAIL" -ne 0 ]; then
    echo "ИТОГ: ЕСТЬ ВЫЖИВШИЕ МУТАЦИИ"; exit 1
fi
echo "ИТОГ: все мутации пойманы, файлы восстановлены побайтово"
