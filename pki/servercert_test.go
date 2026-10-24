// Тесты сертификата сервера агентского API (NR-024).
package pki

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func mustInitDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := InitDir(dir); err != nil {
		t.Fatalf("InitDir: %v", err)
	}
	return dir
}

// Сертификат выпускается один раз и переиспользуется: серийный номер
// при повторном вызове тот же, EKU — ServerAuth, ключ 0600.
func TestEnsureServerCertStable(t *testing.T) {
	dir := mustInitDir(t)
	c1, k1, err := EnsureServerCert(dir)
	if err != nil {
		t.Fatalf("EnsureServerCert: %v", err)
	}
	pair1, err := tls.X509KeyPair(c1, k1)
	if err != nil {
		t.Fatalf("пара не разбирается: %v", err)
	}
	cert1, err := x509.ParseCertificate(pair1.Certificate[0])
	if err != nil {
		t.Fatalf("сертификат: %v", err)
	}
	if cert1.Subject.CommonName != ServerCertCN {
		t.Fatalf("CN = %q, хочу %q", cert1.Subject.CommonName, ServerCertCN)
	}
	hasServerAuth := false
	for _, e := range cert1.ExtKeyUsage {
		if e == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth || len(cert1.ExtKeyUsage) != 1 {
		t.Fatalf("EKU сертификата сервера: %v, хочу только ServerAuth", cert1.ExtKeyUsage)
	}
	// Повторный вызов: тот же сертификат, без перевыпуска.
	c2, k2, err := EnsureServerCert(dir)
	if err != nil {
		t.Fatalf("повторный EnsureServerCert: %v", err)
	}
	if string(c1) != string(c2) || string(k1) != string(k2) {
		t.Fatal("повторный вызов перевыпустил сертификат")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(dir, serverKeyFile))
		if err != nil {
			t.Fatalf("стат ключа: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("права ключа %04o, хочу 0600", perm)
		}
	}
}

// Неполный каталог (сертификат есть, ключа нет) — ошибка, а не
// молчаливый перевыпуск.
func TestEnsureServerCertIncompleteDir(t *testing.T) {
	dir := mustInitDir(t)
	c, _, err := EnsureServerCert(dir)
	if err != nil {
		t.Fatalf("EnsureServerCert: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, serverKeyFile)); err != nil {
		t.Fatalf("удаление ключа: %v", err)
	}
	if _, _, err := EnsureServerCert(dir); err == nil {
		t.Fatal("неполная пара принята")
	}
	_ = c
}
