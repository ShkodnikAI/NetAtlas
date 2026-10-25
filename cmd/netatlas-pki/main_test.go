// Тесты утилиты netatlas-pki (NR-007): init, export-pub печатают
// только публичные материалы; токен регистрации печатается один раз и
// в базе остаётся только хэш.

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ShkodnikAI/NetAtlas/server/store"
)

func capture(f func()) (string, string) {
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	done := make(chan struct{})
	var outBuf, errBuf bytes.Buffer
	go func() {
		_, _ = io.Copy(&outBuf, outR)
		close(done)
	}()
	func() {
		defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
		f()
	}()
	errW.Close()
	outW.Close()
	<-done
	_, _ = io.Copy(&errBuf, errR)
	return outBuf.String(), errBuf.String()
}

const keydirEnv = "NETATLAS_KEYDIR"

// init создаёт файлы и не печатает закрытый материал; export-pub
// печатает публичные PEM.
func TestInitAndExportPub(t *testing.T) {
	dir := t.TempDir()
	getenv := func(k string) string {
		if k == keydirEnv {
			return dir
		}
		return ""
	}
	out, _ := capture(func() {
		if err := run([]string{"init"}, getenv, os.Stdout, os.Stderr); err != nil {
			t.Errorf("init: %v", err)
		}
	})
	if !strings.Contains(out, "ca.key") || strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("вывод init неожиданный: %q", out)
	}
	// Повторный init отказывается перезаписывать.
	if err := run([]string{"init"}, getenv, os.Stdout, os.Stderr); err == nil {
		t.Fatal("повторный init прошёл")
	}

	out2, _ := capture(func() {
		if err := run([]string{"export-pub"}, getenv, os.Stdout, os.Stderr); err != nil {
			t.Errorf("export-pub: %v", err)
		}
	})
	if !strings.Contains(out2, "PUBLIC KEY") || !strings.Contains(out2, "CERTIFICATE") {
		t.Fatalf("export-pub не отдал публичные PEM: %q", out2)
	}

	// Закрытые ключи на диске не просачиваются в вывод.
	priv, err := os.ReadFile(filepath.Join(dir, "sign.key"))
	if err != nil {
		t.Fatalf("sign.key: %v", err)
	}
	block := string(priv)
	if strings.Contains(out, block[:40]) || strings.Contains(out2, block[:40]) {
		t.Fatal("закрытый ключ попал в вывод")
	}
}

// Без NETATLAS_KEYDIR утилита не работает.
func TestKeydirRequired(t *testing.T) {
	getenv := func(string) string { return "" }
	if err := run([]string{"init"}, getenv, os.Stdout, os.Stderr); err == nil {
		t.Fatal("init без NETATLAS_KEYDIR прошёл")
	}
}

// Токен регистрации: печатается один раз, в базе и аудите только
// хэш; revoke добавляет серийный номер.
func TestEnrollTokenAndRevoke(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "netatlas.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	_ = st.Close()

	out, _ := capture(func() {
		if err := run([]string{"enroll-token", "--db", dbPath}, func(string) string { return "" }, os.Stdout, os.Stderr); err != nil {
			t.Errorf("enroll-token: %v", err)
		}
	})
	token := strings.TrimSpace(out)
	if len(token) != 64 {
		t.Fatalf("токен %q длиной %d, хочу 64 hex-символа", token, len(token))
	}
	st2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("повторное открытие: %v", err)
	}
	defer st2.Close()
	// Токен расходуется из базы: он был напечатан, значит действителен.
	if err := st2.ConsumeEnrollToken(t.Context(), token); err != nil {
		t.Fatalf("токен из вывода не расходуется: %v", err)
	}
	// В аудите нет исходного токена.
	rows, err := st2.DB().Query(`SELECT detail FROM audit_log`)
	if err != nil {
		t.Fatalf("аудит: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatalf("detail: %v", err)
		}
		if strings.Contains(d, token) {
			t.Fatal("исходный токен найден в аудите")
		}
	}

	out2, _ := capture(func() {
		if err := run([]string{"revoke", "424242", "--db", dbPath}, func(string) string { return "" }, os.Stdout, os.Stderr); err != nil {
			t.Errorf("revoke: %v", err)
		}
	})
	if !strings.Contains(out2, "424242") {
		t.Fatalf("вывод revoke: %q", out2)
	}
	revoked, err := st2.ListRevoked(t.Context())
	if err != nil {
		t.Fatalf("ListRevoked: %v", err)
	}
	if len(revoked) != 1 || revoked[0] != "424242" {
		t.Fatalf("список отзыва %v", revoked)
	}
}

// TestCLIVersion — --version (NR-027): версия в выводе, без каталога
// ключей и подкоманд.
func TestCLIVersion(t *testing.T) {
	out, _ := capture(func() {
		if err := run([]string{"--version"}, func(string) string { return "" }, os.Stdout, os.Stderr); err != nil {
			t.Errorf("--version: %v", err)
		}
	})
	if !strings.Contains(out, "netatlas ") {
		t.Fatalf("в выводе нет версии: %q", out)
	}
}
