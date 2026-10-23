#!/bin/bash
# NR-022: мутационное тестирование веб-интерфейса (TypeScript).
# Каждая мутация обязана уронить хотя бы один тест; после прогона
# файлы восстанавливаются побайтово.
set -u
cd "$(dirname "$0")/.."
BAK=/tmp/nr022
mkdir -p $BAK
cp web/src/api.ts web/src/nodes.ts web/src/panels.ts $BAK/

mutate_file() { # $1 = путь, $2 = python-код патча
    python3 - "$1" <<EOF
import sys
p = sys.argv[1]
s = open(p).read()
$2
open(p, "w").write(s)
EOF
}

check() { # $1 = имя мутации
    if ! npm test --prefix web >/tmp/nr022_mut.log 2>&1; then
        echo "M($1): поймана — тесты красные"
    else
        echo "M($1): НЕ поймана — тесты зелёные!!!"
        FAIL=1
    fi
    cp $BAK/api.ts $BAK/nodes.ts $BAK/panels.ts web/src/
}

FAIL=0

# M1: обработчик 401 снят (токен не сбрасывается, панель не спрашивается).
mutate_file web/src/api.ts "s = s.replace('res.status === 401', 'res.status === 402')" 
check "M1 обработчик 401 снят"

# M2: формы узлов сняты (все узлы — ellipse).
mutate_file web/src/nodes.ts 's = s.replace("export function nodeStyle(n: NodeInfo): NodeStyle {", "Object.keys(SHAPES).forEach((k) => { SHAPES[k] = \"ellipse\"; });\nexport function nodeStyle(n: NodeInfo): NodeStyle {")'
check "M2 формы узлов сняты"

# M3: безопасная вставка снята (innerHTML вместо textContent).
mutate_file web/src/panels.ts 's = s.replace("function text(parent: HTMLElement, value: string): void {\n  parent.textContent = value;\n}", "function text(parent: HTMLElement, value: string): void {\n  parent.innerHTML = value;\n}")'
check "M3 textContent заменён на innerHTML"

for f in api.ts nodes.ts panels.ts; do
    if ! cmp -s web/src/$f $BAK/$f; then
        echo "ОШИБКА: $f не восстановился"; exit 1
    fi
done
if [ "$FAIL" -ne 0 ]; then
    echo "ИТОГ: ЕСТЬ ВЫЖИВШИЕ МУТАЦИИ"; exit 1
fi
echo "ИТОГ: все мутации пойманы, файлы восстановлены побайтово"
