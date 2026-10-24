//go:build windows

// Права временного файла с проверенным содержимым: только SYSTEM и
// администраторы. Аргументы icacls фиксированы — никакого текста из
// задания в команду не попадает.
package exec

import (
	"fmt"
	"os/exec"
	"strings"
)

// restrict снимает наследование и выдаёт доступ только SYSTEM и
// BUILTIN\Administrators.
func restrict(path string) error {
	cmd := exec.Command("icacls", path, "/inheritance:r",
		"/grant:r", "SYSTEM:F",
		"/grant:r", "BUILTIN\\Administrators:F")
	out, err := cmd.CombinedOutput()
	if err != nil {
		tail := string(out)
		if len(tail) > 200 {
			tail = tail[len(tail)-200:]
		}
		return fmt.Errorf("exec: icacls: %w: %s", err, strings.TrimSpace(tail))
	}
	return nil
}
