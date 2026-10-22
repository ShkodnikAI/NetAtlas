// Package version хранит версию сборки NetAtlas.
package version

// Version — версия сборки; переопределяется при сборке через -ldflags.
var Version = "dev"

// String возвращает строку версии для вывода в консоль.
func String() string {
	return "netatlas " + Version
}
