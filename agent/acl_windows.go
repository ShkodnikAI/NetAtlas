//go:build windows

// Права каталога и файлов агента на Windows: только SYSTEM и
// администраторы. Аргументы icacls фиксированы — никакого текста из
// сети или окружения в команду не попадает.
package agent

import (
	"fmt"
	"os/exec"
)

// restrictACLWindows снимает наследование и выдаёт доступ только
// SYSTEM (*S-1-5-18) и Administrators (*S-1-5-32-544); SID, а не имена: на локализованной Windows имя группы другое. Для каталога флаги наследования
// (OI)(CI), для файла — просто F.
func restrictACLWindows(path string, isDir bool) error {
	grant := "F"
	if isDir {
		grant = "(OI)(CI)F"
	}
	cmd := exec.Command("icacls", path, "/inheritance:r",
		"/grant:r", "*S-1-5-18:"+grant,
		"/grant:r", "*S-1-5-32-544:"+grant)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("agent: icacls %s: %w: %s", path, err, tailOf(out))
	}
	return nil
}

func tailOf(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[len(b)-max:])
	}
	return string(b)
}
