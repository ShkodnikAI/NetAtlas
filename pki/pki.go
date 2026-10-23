// Package pki — собственный центр сертификации NetAtlas и ключи
// подписи заданий. Только стандартная библиотека: сертификаты —
// crypto/x509 + crypto/ecdsa (P-256), подпись заданий — crypto/ed25519
// (server/signing).
//
// Закрытые ключи никогда не покидают каталог ключей NETATLAS_KEYDIR
// (права каталога 0700, файлов 0600); в репозиторий, базу, логи, аудит
// и ответы API они не попадают. На Windows права файлов не
// контролируются средствами Go — ограничение закрывает владелец
// командой icacls (docs/PKI.md).
//
// Агент сам генерирует свой ключ и присылает только запрос на
// сертификат (CSR); закрытый ключ агента не покидает агента.
package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// AgentCertTTL — срок жизни сертификата агента.
const AgentCertTTL = 90 * 24 * time.Hour

// CATTL — срок жизни корневого сертификата.
const CATTL = 10 * 365 * 24 * time.Hour

// ServerCertTTL — срок жизни сертификата сервера.
const ServerCertTTL = 365 * 24 * time.Hour

// Имена файлов каталога ключей: ключ CA отделён от ключа подписи.
const (
	caKeyFile   = "ca.key"
	caCertFile  = "ca.pem"
	signKeyFile = "sign.key"
	signPubFile = "sign.pub"
)

// pkiDirError — ошибка состояния каталога ключей.
func dirErr(what string, err error) error {
	return fmt.Errorf("pki: %s: %w", what, err)
}

// InitDir создаёт каталог ключей и генерирует CA (ECDSA P-256,
// самоподписанный) и ключ подписи заданий (ed25519). Существующие
// файлы не перезаписываются: повторный init на рабочем каталоге —
// ошибка. Закрытые ключи не печатаются и не возвращаются.
func InitDir(dir string) error {
	targets := []string{caKeyFile, caCertFile, signKeyFile, signPubFile}
	for _, f := range targets {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return fmt.Errorf("pki: %s уже существует: init отказывается перезаписывать ключи", filepath.Join(dir, f))
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return dirErr("каталог ключей", err)
	}

	// CA: ECDSA P-256, самоподписанный, только подпись сертификатов.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return dirErr("генерация ключа CA", err)
	}
	serial, err := newSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "NetAtlas Root CA", Organization: []string{"NetAtlas"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(CATTL),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return dirErr("самоподпись CA", err)
	}
	caDERBytes, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return dirErr("кодирование ключа CA", err)
	}
	if err := writePrivatePEM(filepath.Join(dir, caKeyFile), "EC PRIVATE KEY", caDERBytes); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, caCertFile), "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}

	// Ключ подписи заданий: ed25519, отдельный от ключа CA.
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return dirErr("генерация ключа подписи", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(signPriv)
	if err != nil {
		return dirErr("кодирование ключа подписи", err)
	}
	if err := writePrivatePEM(filepath.Join(dir, signKeyFile), "PRIVATE KEY", pkcs8); err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(signPub)
	if err != nil {
		return dirErr("кодирование открытого ключа подписи", err)
	}
	if err := writePEM(filepath.Join(dir, signPubFile), "PUBLIC KEY", pubDER, 0o644); err != nil {
		return err
	}
	return nil
}

// CA — загруженный центр сертификации.
type CA struct {
	Key  *ecdsa.PrivateKey
	Cert *x509.Certificate
}

// LoadCA читает ca.key и ca.pem из каталога ключей. На Linux права
// файла ключа проверяются: лишние права — отказ загрузки.
func LoadCA(dir string) (*CA, error) {
	if err := checkKeyPerms(filepath.Join(dir, caKeyFile)); err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, dirErr("чтение ключа CA", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("pki: %s: не PEM", caKeyFile)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, dirErr("разбор ключа CA", err)
	}
	cert, err := LoadCert(filepath.Join(dir, caCertFile))
	if err != nil {
		return nil, err
	}
	return &CA{Key: key, Cert: cert}, nil
}

// LoadSigningKey читает ключ подписи заданий (ed25519). На Linux права
// файла проверяются.
func LoadSigningKey(dir string) (ed25519.PrivateKey, error) {
	if err := checkKeyPerms(filepath.Join(dir, signKeyFile)); err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, signKeyFile))
	if err != nil {
		return nil, dirErr("чтение ключа подписи", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("pki: %s: не PEM", signKeyFile)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, dirErr("разбор ключа подписи", err)
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("pki: %s: ключ не ed25519", signKeyFile)
	}
	return key, nil
}

// LoadSigningPub читает открытый ключ подписи (для агентов и проверки).
func LoadSigningPub(dir string) (ed25519.PublicKey, error) {
	pubPEM, err := os.ReadFile(filepath.Join(dir, signPubFile))
	if err != nil {
		return nil, dirErr("чтение открытого ключа подписи", err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, fmt.Errorf("pki: %s: не PEM", signPubFile)
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, dirErr("разбор открытого ключа подписи", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pki: %s: ключ не ed25519", signPubFile)
	}
	return pub, nil
}

// LoadCert читает PEM-сертификат.
func LoadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, dirErr("чтение сертификата", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("pki: %s: не PEM", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, dirErr("разбор сертификата", err)
	}
	return cert, nil
}

// IssueServerCert выпускает сертификат сервера: ExtKeyUsage строго
// ServerAuth. Ключ сервера генерируется здесь и возвращается вызывающей
// стороне (PEM); сохранение — ответственность вызывающего.
func (c *CA) IssueServerCert(commonName string, now time.Time) (certPEM, keyPEM []byte, err error) {
	return c.issueLeaf(commonName, now, ServerCertTTL, x509.ExtKeyUsageServerAuth)
}

// SignAgentCSR подписывает запрос на сертификат агента: сертификат
// действует AgentCertTTL (90 дней), ExtKeyUsage строго ClientAuth.
// Подпись CSR проверяется: подделанный запрос отвергается. Одноразовый
// токен регистрации проверяет вызывающая сторона до этого вызова.
func (c *CA) SignAgentCSR(csrPEM []byte, now time.Time) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("pki: CSR агента: не PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: CSR агента: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: CSR агента: подпись запроса не сходится: %w", err)
	}
	return c.issueLeafPEM(csr.Subject.CommonName, now, AgentCertTTL, x509.ExtKeyUsageClientAuth, csr.PublicKey, csr.Subject)
}

// issueLeaf выпускает листовой сертификат с собственным ключом.
func (c *CA) issueLeaf(cn string, now time.Time, ttl time.Duration, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, dirErr("генерация ключа листа", err)
	}
	subject := pkix.Name{CommonName: cn, Organization: []string{"NetAtlas"}}
	certDER, err := c.mint(subject, now, ttl, usage, &key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, dirErr("кодирование ключа листа", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// issueLeafPEM выпускает листовой сертификат по чужому публичному
// ключу (CSR агента).
func (c *CA) issueLeafPEM(cn string, now time.Time, ttl time.Duration, usage x509.ExtKeyUsage, pub any, subject pkix.Name) ([]byte, error) {
	certDER, err := c.mint(subject, now, ttl, usage, pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

// mint подписывает листовой сертификат ключом CA.
func (c *CA) mint(subject pkix.Name, now time.Time, ttl time.Duration, usage x509.ExtKeyUsage, pub any) ([]byte, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, pub, c.Key)
	if err != nil {
		return nil, dirErr("выпуск сертификата", err)
	}
	return der, nil
}

// Verifier проверяет сертификаты при handshake: цепочка до CA, окно
// действия и список отзыва. Роль (client/server)强制 TLS-конфиг —
// ExtKeyUsage выпускаемых сертификатов строго разделены.
type Verifier struct {
	ca   *x509.Certificate
	pool *x509.CertPool
}

// NewVerifier собирает Verifier по сертификату CA.
func NewVerifier(caCert *x509.Certificate) *Verifier {
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &Verifier{ca: caCert, pool: pool}
}

// VerifyPeer проверяет сертификат пира: цепочка до CA, срок действия,
// отсутствие в списке отзыва (серийные номера — десятичные строки).
func (v *Verifier) VerifyPeer(cert *x509.Certificate, revoked []string) error {
	if cert == nil {
		return fmt.Errorf("pki: сертификат пира отсутствует")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     v.pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("pki: цепочка сертификата: %w", err)
	}
	for _, serial := range revoked {
		if cert.SerialNumber.String() == serial {
			return fmt.Errorf("pki: сертификат %s отозван", cert.SerialNumber)
		}
	}
	return nil
}

// CARCert отдаёт сертификат CA (для TLS-конфигов и экспорта).
func (v *Verifier) CACert() *x509.Certificate {
	return v.ca
}

// checkKeyPerms на Linux и macOS требует 0600 у файла закрытого
// ключа: лишние права — отказ загрузки. На Windows права средствами
// Go не контролируются (ограничение, docs/PKI.md).
func checkKeyPerms(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return dirErr("права ключа", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		return fmt.Errorf("pki: права %s: %04o, требуются 0600 — загрузка отвергнута", path, perm)
	}
	return nil
}

// writePrivatePEM пишет закрытый ключ с правами 0600.
func writePrivatePEM(path, typ string, der []byte) error {
	return writePEM(path, typ, der, 0o600)
}

// writePEM пишет PEM-файл с указанными правами.
func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return dirErr("создание "+filepath.Base(path), err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		return dirErr("запись "+filepath.Base(path), err)
	}
	// Права задаются при создании (O_EXCL), но на платформах, где
	// umask мог сузить их, выставляем явно.
	if err := os.Chmod(path, mode); err != nil {
		return dirErr("права "+filepath.Base(path), err)
	}
	return nil
}

// newSerial — случайный положительный серийный номер сертификата.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 64)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, dirErr("серийный номер", err)
	}
	return serial, nil
}

// ErrNoCertPEM — распознаваемая ошибка отсутствия PEM.
var ErrNoCertPEM = errors.New("pki: PEM-блок не найден")
