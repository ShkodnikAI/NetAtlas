// Command netatlas-agent-notify — значок «ПК под наблюдением»
// (NR-012): показывается в области уведомлений всегда, когда сбор
// активности включён на этой машине (файл статуса от агента),
// всплывает при включении; когда выключен — значка нет. Запускается
// вместе с агентом (автозагрузка пользователя, см. install/uninstall).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// statusFile — файл статуса от агента в каталоге состояния.
const statusFile = "activity-status.json"

// pollInterval — период чтения статуса.
const pollInterval = 30 * time.Second

// defaultDir — каталог состояния агента (как у агента: переменная
// NETATLAS_AGENT_DIR или ProgramData).
func defaultDir() string {
	if d := os.Getenv("NETATLAS_AGENT_DIR"); d != "" {
		return d
	}
	if p := os.Getenv("ProgramData"); p != "" {
		return filepath.Join(p, "NetAtlas", "agent")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".netatlas-agent")
}

// status — чтение файла статуса; нет файла/битый — выключено.
func status(dir string) bool {
	raw, err := os.ReadFile(filepath.Join(dir, statusFile))
	if err != nil {
		return false
	}
	var st struct {
		ActivityEnabled bool `json:"activity_enabled"`
	}
	if json.Unmarshal(raw, &st) != nil {
		return false
	}
	return st.ActivityEnabled
}

func main() {
	dir := defaultDir()
	if d := os.Getenv("NETATLAS_NOTIFY_DIR"); d != "" {
		dir = d // точка подмены в тестах
	}
	if err := runLoop(dir); err != nil {
		fmt.Fprintf(os.Stderr, "netatlas-agent-notify: %v\n", err)
		os.Exit(1)
	}
}
