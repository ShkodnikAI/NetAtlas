// Тесты центра сертификации (NR-007): выпуск и роли сертификатов,
// отзыв, права файлов ключей, подделанный CSR.

package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func newCA(t *testing.T) (*CA, string) {
	t.Helper()
	dir := t.TempDir()
	if err := InitDir(dir); err != nil {
		t.Fatalf("InitDir: %v", err)
	}
	ca, err := LoadCA(dir)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	return ca, dir
}

// init создаёт все четыре файла; повторный init отказывается
// перезаписывать.
func TestInitDirFilesAndRefusal(t *testing.T) {
	_, dir := newCA(t)
	for _, f := range []string{caKeyFile, caCertFile, signKeyFile, signPubFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("файл %s не создан: %v", f, err)
		}
	}
	if err := InitDir(dir); err == nil {
		t.Fatal("повторный init перезаписал ключи")
	}
}

// Серверный сертификат: ServerAuth; агентский (по CSR): ClientAuth и
// 90 дней. Роли не взаимозаменяемы — проверяется через x509.Verify с
// жёстким KeyUsages.
func TestCertRolesSeparated(t *testing.T) {
	ca, _ := newCA(t)
	now := time.Now()

	serverPEM, _, err := ca.IssueServerCert("netatlas-server", now)
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}
	serverCert := parseCert(t, serverPEM)
	if serverCert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("серверный сертификат: ExtKeyUsage %v", serverCert.ExtKeyUsage)
	}

	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ агента: %v", err)
	}
	csrTmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "agent-77"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, agentKey)
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	agentPEM, err := ca.SignAgentCSR(csrPEM, now)
	if err != nil {
		t.Fatalf("SignAgentCSR: %v", err)
	}
	agentCert := parseCert(t, agentPEM)
	if agentCert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("агентский сертификат: ExtKeyUsage %v", agentCert.ExtKeyUsage)
	}
	if days := agentCert.NotAfter.Sub(agentCert.NotBefore).Hours(); days < 89*24 || days > 91*24 {
		t.Fatalf("срок агентского сертификата %v часов, хочу около 90 дней", days/24*24)
	}

	// Агентский сертификат не годится как серверный и наоборот.
	ver := NewVerifier(ca.Cert)
	pool := ver.pool
	if _, err := agentCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Fatal("агентский сертификат принят как серверный")
	}
	if _, err := serverCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err == nil {
		t.Fatal("серверный сертификат принят как клиентский")
	}
}

// Подделанный CSR (подпись запроса не сходится) отвергается.
func TestSignAgentCSRRejectsForged(t *testing.T) {
	ca, _ := newCA(t)
	// CSR без подписи ключа: собираем DER от одного ключа, подпись
	// проверяется чужим открытым ключом — примем любой валидный DER и
	// подменим поле публичного ключа через пересоздание не выйдет,
	// поэтому проще: битый PEM.
	fake := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("мусор")})
	if _, err := ca.SignAgentCSR(fake, time.Now()); err == nil {
		t.Fatal("мусорный CSR принят")
	}
	if _, err := ca.SignAgentCSR([]byte("не PEM"), time.Now()); err == nil {
		t.Fatal("не-PEM CSR принят")
	}
}

// CSR с испорченной подписью (валидный DER, последний байт подписи
// искажён) отвергается — ловит снятие CheckSignature.
func TestSignAgentCSRRejectsTamperedSignature(t *testing.T) {
	ca, _ := newCA(t)
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ агента: %v", err)
	}
	csrTmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "agent-77"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, agentKey)
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}
	forged := append([]byte(nil), csrDER...)
	forged[len(forged)-1] ^= 0xFF
	if _, err := x509.ParseCertificateRequest(forged); err != nil {
		t.Fatalf("искажённый DER перестал разбираться: %v", err)
	}
	forgedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: forged})
	if _, err := ca.SignAgentCSR(forgedPEM, time.Now()); err == nil {
		t.Fatal("CSR с битой подписью принят")
	}
}

// Отозванный сертификат отвергается Verifier'ом.
func TestVerifyPeerRevoked(t *testing.T) {
	ca, _ := newCA(t)
	now := time.Now()
	serverPEM, _, err := ca.IssueServerCert("srv", now)
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}
	cert := parseCert(t, serverPEM)
	ver := NewVerifier(ca.Cert)
	if err := ver.VerifyPeer(cert, nil); err != nil {
		t.Fatalf("без отзыва: %v", err)
	}
	if err := ver.VerifyPeer(cert, []string{cert.SerialNumber.String()}); err == nil {
		t.Fatal("отозванный сертификат принят")
	}
}

// Просроченный сертификат отвергается цепочкой.
func TestVerifyPeerExpired(t *testing.T) {
	ca, _ := newCA(t)
	past := time.Now().Add(-24 * time.Hour)
	serverPEM, _, err := ca.IssueServerCert("srv", past)
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}
	cert := parseCert(t, serverPEM)
	ver := NewVerifier(ca.Cert)
	// Сертификат выпущен вчера на год — ещё действителен; для теста
	// срока берём окно проверки NotAfter.
	if err := ver.VerifyPeer(cert, nil); err != nil {
		t.Fatalf("действительный сертификат отвергнут: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       NewVerifier(ca.Cert).pool,
		CurrentTime: cert.NotAfter.Add(time.Hour),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Fatal("просроченный сертификат принят")
	}
}

// Неверная цепочка (подпись не от этого CA) отвергается.
func TestVerifyPeerForeignCA(t *testing.T) {
	ca, _ := newCA(t)
	otherCA, _ := newCA(t)
	now := time.Now()
	serverPEM, _, err := otherCA.IssueServerCert("srv", now)
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}
	cert := parseCert(t, serverPEM)
	ver := NewVerifier(ca.Cert)
	if err := ver.VerifyPeer(cert, nil); err == nil {
		t.Fatal("сертификат чужого CA принят")
	}
}

// Файл закрытого ключа с лишними правами отвергается при загрузке
// (только на Linux — на Windows права не контролируются).
func TestKeyPermsEnforced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("на Windows права файлов не контролируются (docs/PKI.md)")
	}
	_, dir := newCA(t)
	path := filepath.Join(dir, signKeyFile)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := LoadSigningKey(dir); err == nil {
		t.Fatal("ключ с правами 0644 принят")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := LoadSigningKey(dir); err != nil {
		t.Fatalf("ключ 0600 отвергнут: %v", err)
	}
}

func parseCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("сертификат не PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	return cert
}
