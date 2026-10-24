//go:build !windows

// На не-Windows права задаются chmod'ом в keydir.go; сюда вызов
// icacls не доходит (защищён runtime.GOOS == "windows").
package agent

import "errors"

func restrictACLWindows(path string, isDir bool) error {
	return errors.New("agent: icacls недоступен вне Windows")
}
