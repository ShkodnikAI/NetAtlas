// TLS-клиент агента: доверие закрепляется корневым сертификатом
// нашего CA (agent-ca.pem), клиентский сертификат — от того же CA.
// TLS 1.3, проверка цепочки в VerifyPeerCertificate (сертификат
// сервера не имеет SAN: идентичность — принадлежность к нашему CA,
// приватная сеть). Агент только инициирует соединения и не слушает
// никаких портов.
package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// DefaultPollInterval — интервал опроса по умолчанию (наряд: 15
// минут; сервер может скорректировать в ответе checkin).
const DefaultPollInterval = 15 * time.Minute

// agentIDPrefix — схема личности агента, совпадает с серверной.
const agentIDPrefix = "agent:"

// LoadTLS собирает конфигурацию TLS агента из каталога состояния:
// клиентский сертификат + ключ, корень — только наш CA, минимум
// TLS 1.3, проверка цепочки сервера в VerifyPeerCertificate.
func LoadTLS(dir string) (*tls.Config, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, certFile))
	if err != nil {
		return nil, fmt.Errorf("agent: сертификат: %w (сначала enroll)", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, fmt.Errorf("agent: ключ: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, caFile))
	if err != nil {
		return nil, fmt.Errorf("agent: корневой сертификат: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("agent: пара сертификат/ключ: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("agent: ca.pem не содержит сертификат")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
		// Сертификат сервера без SAN: принадлежность нашему CA
		// проверяем сами, имя хоста не сверяем (DNSName пуст).
		InsecureSkipVerify:    true, // имя хоста не сверяем: identity — наш CA
		VerifyPeerCertificate: chainVerifier(pool),
	}, nil
}

// chainVerifier проверяет цепочку сервера против закреплённого CA.
func chainVerifier(pool *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
		if len(chains) > 0 {
			return nil // TLS уже проверил цепочку
		}
		if len(rawCerts) == 0 {
			return errors.New("agent: сервер не предъявил сертификат")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("agent: сертификат сервера: %w", err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
			return fmt.Errorf("agent: сервер не от нашего CA: %w", err)
		}
		return nil
	}
}

// Enroll регистрирует агента: корневой сертификат (--ca) копируется
// в каталог состояния, ключ создаётся один раз, CSR с
// CN=agent:<uuid> уходит на сервер, сертификат сохраняется. Токен
// не сохраняется и не логируется. Возвращает agent_id.
func Enroll(ctx context.Context, serverURL, token, dir, caSrc string) (string, error) {
	if token == "" {
		return "", errors.New("agent: пустой токен регистрации")
	}
	if err := EnsureDir(dir); err != nil {
		return "", err
	}
	caPEM, err := os.ReadFile(caSrc)
	if err != nil {
		return "", fmt.Errorf("agent: корневой сертификат %s: %w", caSrc, err)
	}
	pool := pemPool(caPEM)
	if !pool.AppendCertsFromPEM(caPEM) {
		return "", errors.New("agent: файл --ca не содержит сертификат")
	}
	// CA закрепляется в каталоге состояния: дальше агент доверяет
	// только ему.
	if err := writePublic(filepath.Join(dir, caFile), caPEM); err != nil {
		return "", err
	}
	keyPEM, err := ensureKey(dir)
	if err != nil {
		return "", err
	}
	csrPEM, err := makeCSR(keyPEM)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(enrollRequest{
		Token:    token,
		CSRPEM:   string(csrPEM),
		Hostname: hostname(),
		MACs:     localMACs(),
	})
	if err != nil {
		return "", err
	}
	cfg := &tls.Config{
		RootCAs:               pemPool(caPEM),
		MinVersion:            tls.VersionTLS13,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: chainVerifier(pemPool(caPEM)),
	}
	hc := &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg},
		Timeout:   30 * time.Second,
	}
	resp, err := hc.Post(strings.TrimSuffix(serverURL, "/")+"/agent/v1/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("agent: enroll: %w", err)
	}
	defer resp.Body.Close()
	var out enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("agent: ответ enroll (%d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusCreated {
		// Тело ошибки может повторить ввод; agent_id не печатаем
		// из ответа ошибки — только статус.
		return "", fmt.Errorf("agent: enroll отклонён: код %d", resp.StatusCode)
	}
	if !strings.HasPrefix(out.AgentID, agentIDPrefix) {
		return "", fmt.Errorf("agent: сервер вернул неожиданную личность")
	}
	if err := writePublic(filepath.Join(dir, certFile), []byte(out.CertPEM)); err != nil {
		return "", err
	}
	return out.AgentID, nil
}

// enrollRequest — тело регистрации (совпадает с серверным контрактом).
type enrollRequest struct {
	Token    string   `json:"token"`
	CSRPEM   string   `json:"csr_pem"`
	Hostname string   `json:"hostname"`
	MACs     []string `json:"macs"`
}

// enrollResponse — ответ регистрации.
type enrollResponse struct {
	CertPEM string `json:"cert_pem"`
	AgentID string `json:"agent_id"`
	PollSec int    `json:"poll_interval_s"`
}

// makeCSR — запрос на сертификат от ключа агента.
func makeCSR(keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("agent: ключ агента не PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("agent: ключ агента: %w", err)
	}
	req := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: agentIDPrefix + uuid.NewString(), Organization: []string{"NetAtlas"}},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		return nil, fmt.Errorf("agent: CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// newAgentKey — новая пара ECDSA P-256 (PEM).
func newAgentKey() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("agent: ключ: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("agent: кодирование ключа: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// Checkin — heartbeat; ответ несёт список заданий (NR-011) и
// интервал опроса.
type Checkin struct {
	Jobs    []json.RawMessage `json:"jobs"`
	PollSec int               `json:"poll_interval_s"`
}

// SendInventory отправляет порцию инвентаря (готовое тело конверта).
type Transport interface {
	Checkin(ctx context.Context) (Checkin, error)
	SendInventory(ctx context.Context, body []byte) error
}

// Client — HTTP-клиент агентских маршрутов по mTLS.
type Client struct {
	base string
	hc   *http.Client
}

// NewClient строит клиент по каталогу состояния и адресу сервера.
func NewClient(serverURL, dir string) (*Client, error) {
	cfg, err := LoadTLS(dir)
	if err != nil {
		return nil, err
	}
	return &Client{
		base: strings.TrimSuffix(serverURL, "/"),
		hc: &http.Client{
			Transport: &http.Transport{TLSClientConfig: cfg},
			Timeout:   60 * time.Second,
		},
	}, nil
}

// Checkin — POST /agent/v1/checkin.
func (c *Client) Checkin(ctx context.Context) (Checkin, error) {
	resp, err := c.hc.Post(c.base+"/agent/v1/checkin", "application/json", nil)
	if err != nil {
		return Checkin{}, fmt.Errorf("agent: checkin: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Checkin{}, fmt.Errorf("agent: checkin: код %d", resp.StatusCode)
	}
	var out Checkin
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Checkin{}, fmt.Errorf("agent: ответ checkin: %w", err)
	}
	return out, nil
}

// SendInventory — POST /agent/v1/inventory с готовым конвертом.
func (c *Client) SendInventory(ctx context.Context, body []byte) error {
	resp, err := c.hc.Post(c.base+"/agent/v1/inventory", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("agent: inventory: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("agent: inventory: код %d", resp.StatusCode)
	}
	return nil
}

// InventoryEnvelope — конверт отправления: сервер требует kind,
// schema_ver, collected_at, payload.
type InventoryEnvelope struct {
	Kind        string          `json:"kind"`
	SchemaVer   int             `json:"schema_ver"`
	CollectedAt time.Time       `json:"collected_at"`
	Payload     json.RawMessage `json:"payload"`
}

// pemPool — CertPool из PEM-байтов.
func pemPool(caPEM []byte) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return pool
}

// hostname — имя машины (ошибка не роняет: пусто).
func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// localMACs — MAC-адреса живых физических интерфейсов (для
// привязки к устройствам карты на сервере).
func localMACs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{}
	}
	out := []string{}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		if len(ifc.HardwareAddr) == 0 {
			continue
		}
		out = append(out, ifc.HardwareAddr.String())
	}
	return out
}
