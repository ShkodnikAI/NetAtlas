// Package web — встроенный веб-интерфейс: коммитящаяся сборка
// web/dist отдаётся сервером на корне. Сборка не содержит внешних
// ссылок: всё локально (нет CDN, шрифтов и аналитики).
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler отдаёт сборку интерфейса: index.html для неизвестных путей
// (одностраничный интерфейс), файлы — как есть.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		// embed гарантированно содержит dist: ошибка невозможна.
		panic("web: сборка dist недоступна: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err != nil {
			// Неизвестный путь — корень интерфейса.
			http.ServeFileFS(w, r, sub, "index.html")
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
