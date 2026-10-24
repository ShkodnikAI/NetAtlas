//go:build windows

// Служба Windows (NR-006): golang.org/x/sys/windows/svc — единственная
// новая зависимость. Агент ничего не слушает, только инициирует
// соединения.
package agent

import (
	"context"

	"golang.org/x/sys/windows/svc"
)

// ServiceName — имя службы в SCM.
const ServiceName = "NetAtlasAgent"

// serviceHandler — мост между SCM и Runner.
type serviceHandler struct {
	serverURL string
	dir       string
}

// Execute — контракт svc.Handler.
func (h *serviceHandler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	runner, err := NewRunner(h.serverURL, h.dir)
	if err != nil {
		status <- svc.Status{State: svc.Stopped}
		return false, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()

	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				if err := <-done; err != nil {
					return false, 1
				}
				return false, 0
			default:
				status <- svc.Status{State: svc.StopPending}
				return false, 2
			}
		case err := <-done:
			status <- svc.Status{State: svc.Stopped}
			if err != nil {
				return false, 3
			}
			return false, 0
		}
	}
}

// RunService запускает службу (вызывается SCM, не владелец).
func RunService(serverURL, dir string) error {
	return svc.Run(ServiceName, &serviceHandler{serverURL: serverURL, dir: dir})
}

// IsWindowsService — запущены ли как служба.
func IsWindowsService() (bool, error) {
	return svc.IsWindowsService()
}
