# NetAtlas: установка и работа (Windows 10/11, PowerShell 5.1)

Всё делается вставкой команд в окно **PowerShell (администратор)**.
Результаты (текст без секретов) возвращаете аудитору. Токены никуда
не вставляются: они в файлах с закрытыми правами и в буфере обмена.

Требования: Windows 10/11 или Windows Server, Windows PowerShell 5.1
(есть в системе по умолчанию; `pwsh` не нужен), права администратора.

## 1. Установка сервера (две строки)

Первая строка скачивает релиз с контрольной суммой и распаковывает;
вторая — запускает установку. Установка сама проверит хэш архива,
закроет права, создаст ключи, токен (появится в буфере обмена — в чат
не вставлять), определит подсеть (спросит подтверждение), поставит
задачу автозапуска и дождётся ответа сервера.

```powershell
$v = (Invoke-RestMethod 'https://api.github.com/repos/ShkodnikAI/NetAtlas/releases/latest').tag_name; $z = "$env:TEMP\netatlas.zip"; Invoke-WebRequest "https://github.com/ShkodnikAI/NetAtlas/releases/download/$v/netatlas-$v-windows-amd64.zip" -OutFile $z; Expand-Archive $z "$env:TEMP\netatlas-release" -Force
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\netatlas-release\scripts\install\Install-NetAtlas.ps1" -Yes
```

Если репозиторий закрыт и скачивание не удалось: скачайте архив
`netatlas-<версия>-windows-amd64.zip` и `SHA256SUMS.txt` вручную
(аудитор передаст), затем установите из файла:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<путь>\scripts\install\Install-NetAtlas.ps1" -ZipPath "<путь>\netatlas-v0.1.0-windows-amd64.zip" -Yes
```

После установки: сервер работает как задача планировщика
`NetAtlasServer`, адрес владельца — `http://127.0.0.1:8484`
(только этот компьютер), журнал — `C:\NetAtlas\logs`.

## 2. Сканирование сети (одна команда)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\NetAtlas\app\scripts\install\Start-NetAtlasScan.ps1"
```

Напечатает сводку: устройства по классам, хосты без MAC, ошибки
этапов, длительность. SNMP-опрос портов (по желанию):
`... -SnmpTargets 192.168.1.1`.

## 3. Отчёт для аудитора (одна команда)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\NetAtlas\app\scripts\install\Get-NetAtlasReport.ps1"
```

Печатает отчёт без секретов (версия, Windows, задача и порт,
конфигурация, цепочка аудита, число устройств/связей/агентов, последние
30 строк журнала с маскированием) и сохраняет его в
`C:\NetAtlas\logs\report-<время>.txt` — файл и текст можно отправлять
аудитору.

## Что ещё полезно

- Проверка архива релиза: `scripts\Verify-Release.ps1 -ZipPath <архив> -SumsPath SHA256SUMS.txt`
- Заменить токен владельца: `Install-NetAtlas.ps1 -RotateToken -Yes` (старый перестанет работать)
- Удалить сервер: `Uninstall-NetAtlas.ps1` (задача и брандмауэр); с `-Confirm` — и каталог; `-Confirm -KeepData` сохранит базу, ключи и токен
- Подсети вручную: `Install-NetAtlas.ps1 -Subnets 192.168.1.0/24 -Yes`
- Подключение компьютеров-агентов — см. разделы ниже (NR-029)

## Сервер: выдать приглашение агенту (NR-029)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\NetAtlas\app\scripts\install\New-AgentInvite.ps1" -ComputerName PC-01 -Yes
```

Создаст `C:\NetAtlas\invites\<имя>-<время>\` (zip и файлы приглашения).
Передайте папку или zip на целевой компьютер по сети или на флешке.
Режим `-Serve` поднимает временный раздатчик архива в локальной сети
на 15 минут (по умолчанию выключен; токен регистрации одноразовый и
живёт один час).

## Компьютер: вставить и поставить (NR-029)

На целевом компьютере (PowerShell, администратор) — из папки приглашения:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<путь к папке приглашения>\Install-Agent.ps1" -Yes
```

Агент регистрируется и ставится службой (запуск — после подтверждения
`-Yes`); токен регистрации удаляется с диска после установки.

Отчёт о состоянии агента для аудитора — тоже из папки приглашения:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<путь к папке приглашения>\Get-AgentReport.ps1"
```

Удаление агента — `Uninstall-Agent.ps1` из той же папки приглашения
(`-Confirm` удаляет и каталог состояния агента).
