//go:build windows

// Установка, удаление и статус службы (NR-006): golang.org/x/sys/windows/svc/mgr.
// Учётная запись — виртуальная NT SERVICE\NetAtlasAgent (минимум прав,
// файлы агента доступны по ACL только SYSTEM/администраторам).
// Служба создаётся остановленной: стартует её владелец.
package agent

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Install регистрирует службу: автоматический старт при загрузке,
// аргументы — run --server ... --dir .... Уже установленная служба —
// ошибка. Служба создаётся остановленной.
func Install(serverURL, dir string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("agent: путь бинаря: %w", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("agent: SCM (нужны права администратора): %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(ServiceName); err == nil {
		s.Close()
		return fmt.Errorf("agent: служба %s уже установлена", ServiceName)
	}
	s, err := m.CreateService(ServiceName, exe, mgr.Config{
		StartType:        mgr.StartAutomatic,
		DisplayName:      "NetAtlas Agent",
		Description:      "Агент инвентаря NetAtlas: только чтение, ничего не исполняет (NR-006)",
		ServiceStartName: "NT SERVICE\\" + ServiceName,
	}, "run", "--server", serverURL, "--dir", dir)
	if err != nil {
		return fmt.Errorf("agent: создание службы: %w", err)
	}
	defer s.Close()
	return nil
}

// Uninstall останавливает (если запущена) и удаляет службу.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("agent: SCM (нужны права администратора): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("agent: служба %s не установлена: %w", ServiceName, err)
	}
	defer s.Close()
	if status, err := s.Query(); err == nil && status.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if st, err := s.Query(); err == nil && st.State == svc.Stopped {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("agent: удаление службы: %w", err)
	}
	return nil
}

// StatusState — состояние службы строкой.
func StatusState() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("agent: SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "not installed", nil
		}
		return "", fmt.Errorf("agent: служба %s: %w", ServiceName, err)
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "", fmt.Errorf("agent: статус службы: %w", err)
	}
	switch st.State {
	case svc.Stopped:
		return "stopped", nil
	case svc.Running:
		return "running", nil
	case svc.StartPending:
		return "starting", nil
	case svc.StopPending:
		return "stopping", nil
	case svc.Paused, svc.PausePending, svc.ContinuePending:
		return "paused", nil
	default:
		return "unknown", nil
	}
}
