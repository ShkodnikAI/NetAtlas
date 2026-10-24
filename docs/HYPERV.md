# Тестовый стенд Hyper-V (NR-026)

Стенд — изолированная тестовая сеть на вашей машине: скрипт проверяется
на чистой виртуальной машине перед подписью, после каждого теста
машина возвращается в эталонное состояние. Исполнитель (агент) ни при
чём: стенд нужен до подписи, исполнение на рабочих машинах — отдельно
(NR-025).

**Всё, что делают скрипты стенда, требует явного `-Confirm`.** Без него
скрипт показывает план (режим `-WhatIf`) и ничего не трогает.

## Проверка редакции Windows

Hyper-V работает в Pro, Enterprise и Education (Home — нет):

```powershell
(Get-CimInstance Win32_OperatingSystem).Caption
```

## Включение Hyper-V

От администратора (PowerShell):

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All
```

Перезагрузка. Проверка: `Get-Command Get-VM` — командлет доступен.
Альтернатива: «Панель управления → Программы → Включение или отключение
компонентов Windows → Hyper-V».

## Подготовка эталонного образа

1. Создайте ВМ с Windows 10/11 (Gen 2), поставьте минимум: систему,
   PowerShell, обновления. ВМ не должна быть привязана к вашему
   аккаунту (локальный администратор).
2. Внутри ВМ включите PowerShell Remoting для PowerShell Direct —
   он включён по умолчанию для локальных администраторов; убедитесь,
   что пароль локального администратора вам известен.
3. Выключите ВМ, экспортируйте диск (или скопируйте VHDX) — это и есть
   эталонный образ, путь понадобится скриптам:

```powershell
Copy-Item 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\эталон.vhdx' D:\images\win11-ethalon.vhdx
```

## Поднятие стенда

```powershell
cd scripts\hyperv
.\New-TestNetwork.ps1 -ImagePath D:\images\win11-ethalon.vhdx -WhatIf   # план
.\New-TestNetwork.ps1 -ImagePath D:\images\win11-ethalon.vhdx -Confirm  # создать
```

Что получится: коммутатор `NetAtlas-Test-Switch` (Private — без доступа
в вашу сеть), ВМ `NetAtlas-Test-VM1`, `NetAtlas-Test-VM2` (счётчик
`-VMCount 3`), на каждой снимок-эталон `NetAtlas-эталон`. Копирование
образа: с ВМ на диск вашей машины — извне стенд не доступен.

## Прогон скрипта перед подписью

Статические проверки (не нужны ни Hyper-V, ни администратор):

```powershell
.\Invoke-StaticCheck.ps1 -ScriptPath C:\scripts\my-script.ps1
```

Тест на ВМ (восстановит снимок, скопирует скрипт, запустит, соберёт
метрики до/после — задержка, свободное место, службы, откатит снимок):

```powershell
$cred = Get-Credential   # локальный администратор ВМ
.\Invoke-ScriptTest.ps1 -ScriptPath C:\scripts\my-script.ps1 `
    -VMName NetAtlas-Test-VM1 -Credential $cred -Confirm
```

С отправкой результата прямо в конвейер (статус версии обновится,
`vm pass` переведёт `checked → tested`):

```powershell
.\Invoke-ScriptTest.ps1 -ScriptPath C:\scripts\my-script.ps1 `
    -VMName NetAtlas-Test-VM1 -Credential $cred `
    -Token <ваш NETATLAS_TOKEN> -Confirm
```

Каждый прогон пишет JSON-файл рядом со скриптом
(`test-result-ГГГГММДД-ЧЧММСС.json`): хэш скрипта, итог, метрики, лог.
Файл можно отправить позже вручную:

```powershell
$body = Get-Content .\test-result-20261025-120000.json -Raw
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8484/api/test-runs `
    -Headers @{ Authorization = "Bearer <токен>" } -Body $body -ContentType 'application/json'
```

Что видно на сервере: карточка скрипта → проверки и тесты (источник
«стенд»), статус версии после проходного теста — «Тест на ВМ»,
записи `script_check` в журнале аудита. Результат со стенда
связывается с версией по хэшу содержимого: хэш не совпал — результат
отвергается.

## Удаление стенда

```powershell
.\Remove-TestNetwork.ps1 -WhatIf    # что будет удалено
.\Remove-TestNetwork.ps1 -Confirm   # удалить
```

Удаляются **только** объекты с префиксом `NetAtlas-Test-`: ваши ВМ,
коммутаторы и диски вне стенда не трогаются.
