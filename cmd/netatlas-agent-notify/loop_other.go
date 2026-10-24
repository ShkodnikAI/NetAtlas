//go:build !windows

// Вне Windows значок не существует: целевые машины — Windows.
// Цикл чтения статуса работает (для тестов), отображения нет.
package main

import "time"

// runLoop — без отображения: только чтение статуса (совместимость
// со средой разработки; на целевых машинах всегда Windows).
func runLoop(dir string) error {
	for {
		time.Sleep(pollInterval)
		_ = status(dir)
	}
}
