// Package version хранит версию сборки NetAtlas.
package version

// Version — версия сборки; переопределяется при сборке через -ldflags.
var Version = "dev"

// CommitDate — дата коммита (UTC, RFC3339); переопределяется при
// сборке через -ldflags. Нужна отчётам для аудитора (NR-028): версия
// и дата сборки печатаются без доступа к сети.
var CommitDate = "unknown"

// String возвращает строку версии для вывода в консоль.
func String() string {
	return "netatlas " + Version
}
