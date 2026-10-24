// Тесты агентского API (NR-024): настоящий TLS на 127.0.0.1 в
// процессе теста (разрешено нарядом), внешней сети нет. Негативные
// сценарии: без сертификата, чужой CA, просроченный, отозванный,
// серверный сертификат как клиентский, токены, лимиты, подмена
// личности. Тесты обязаны падать, если снять RequireAndVerifyClientCert
// или проверку отзыва.
package agentapi

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
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/pki"
	"github.com/ShkodnikAI/NetAtlas/server/audit"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

const testCN = "agent:11111111-2222-3333-4444-555555555555"

// env — поднятый агентский API на локальных эфемерных портах.
type env struct {
	t          *testing.T
	st         *store.Store
	api        *API
	ca         *pki.CA
	mtlsAddr   string
	enrollAddr string
}

func newEnv(t *testing.T, revTTL time.Duration) *env {
	t.Helper()
	keyDir := t.TempDir()
	if err := pki.InitDir(keyDir); err != nil {
		t.Fatalf("InitDir: %v", err)
	}
	ca, err := pki.LoadCA(keyDir)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "netatlas.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	api, err := New(st, ca, 2*time.Second)
	if err != nil {
		t.Fatalf("agentapi.New: %v", err)
	}
	api.SetRevocationTTL(revTTL)
	certPEM, keyPEM, err := pki.EnsureServerCert(keyDir)
	if err != nil {
		t.Fatalf("EnsureServerCert: %v", err)
	}
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("пара сервера: %v", err)
	}
	mLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mTLS-слушатель: %v", err)
	}
	eLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("слушатель регистрации: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = Serve(ctx, mLn, api.MTLSConfig(serverCert), api.MTLSHandler()) }()
	go func() { _ = Serve(ctx, eLn, api.EnrollConfig(serverCert), api.EnrollHandler()) }()
	t.Cleanup(func() {
		cancel()
		st.Close()
	})
	return &env{
		t:          t,
		st:         st,
		api:        api,
		ca:         ca,
		mtlsAddr:   mLn.Addr().String(),
		enrollAddr: eLn.Addr().String(),
	}
}

func (e *env) enrollURL() string { return "https://" + e.enrollAddr + "/agent/v1/enroll" }

func (e *env) mtlsURL(path string) string { return "https://" + e.mtlsAddr + path }

// post — запрос по TLS, ответ разбирается; ошибка транспорта — падение.
func (e *env) post(cl *http.Client, url string, body []byte) (int, []byte) {
	e.t.Helper()
	resp, err := cl.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		e.t.Fatalf("запрос %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("чтение ответа: %v", err)
	}
	return resp.StatusCode, raw
}

// requestRejected — запрос обязан не дойти (отказ на handshake).
func (e *env) requestRejected(cl *http.Client, url string) {
	e.t.Helper()
	resp, err := cl.Post(url, "application/json", bytes.NewReader([]byte("{}")))
	if err == nil {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		e.t.Fatalf("запрос %s прошёл с кодом %d, хочу отказ на handshake: %s", url, resp.StatusCode, raw)
	}
}

// plainClient — TLS-клиент без клиентского сертификата.
func plainClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true, // каждый запрос — новое handshake
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // серверный сертификат не предмет теста
				MinVersion:         tls.VersionTLS13,
			},
		},
		Timeout: 10 * time.Second,
	}
}

// certClient — TLS-клиент с готовой парой (DER + ключ).
func certClient(certDER []byte, priv any) *http.Client {
	cert := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: priv}
	return &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true, // каждый запрос — новое handshake
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{cert},
				MinVersion:         tls.VersionTLS13,
			},
		},
		Timeout: 10 * time.Second,
	}
}

// tls12Client — клиент с валидной парой, настаивающий на TLS 1.2.
func tls12Client(certDER []byte, priv any) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true, // каждый запрос — новое handshake
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: priv}},
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS12,
			},
		},
		Timeout: 10 * time.Second,
	}
}

// newCSRPair — ключ и подписанный CSR с заданным CN.
func newCSRPair(t *testing.T, cn string) (csrPEM []byte, priv *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ агента: %v", err)
	}
	req := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn, Organization: []string{"NetAtlas"}},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

// issueToken — токен регистрации от владельца.
func (e *env) issueToken() string {
	e.t.Helper()
	token, err := e.st.IssueEnrollToken(context.Background(), "owner")
	if err != nil {
		e.t.Fatalf("IssueEnrollToken: %v", err)
	}
	return token
}

// enrollAgent — полный путь регистрации: токен → CSR → сертификат.
func (e *env) enrollAgent(cn, hostname string, macs []string) (certPEM string, serial string, priv *ecdsa.PrivateKey) {
	e.t.Helper()
	token := e.issueToken()
	csrPEM, priv := newCSRPair(e.t, cn)
	req := enrollRequest{Token: token, CSRPEM: string(csrPEM), Hostname: hostname, MACs: macs}
	body, err := json.Marshal(req)
	if err != nil {
		e.t.Fatalf("тело регистрации: %v", err)
	}
	code, resp := e.post(plainClient(), e.enrollURL(), body)
	if code != http.StatusCreated {
		e.t.Fatalf("регистрация %s: код %d: %s", cn, code, resp)
	}
	var out enrollResponse
	if err := json.Unmarshal(resp, &out); err != nil {
		e.t.Fatalf("ответ регистрации не разбирается: %v", err)
	}
	if out.AgentID != cn {
		e.t.Fatalf("agent_id = %q, хочу CN %q", out.AgentID, cn)
	}
	block, _ := pem.Decode([]byte(out.CertPEM))
	if block == nil {
		e.t.Fatalf("сертификат регистрации не PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		e.t.Fatalf("сертификат регистрации: %v", err)
	}
	if cert.Subject.CommonName != cn {
		e.t.Fatalf("CN сертификата %q, хочу %q", cert.Subject.CommonName, cn)
	}
	// Серийник в базе совпадает с выданным сертификатом.
	agent, err := e.st.AgentByID(context.Background(), cn)
	if err != nil {
		e.t.Fatalf("AgentByID: %v", err)
	}
	if agent.CertSerial != cert.SerialNumber.String() {
		e.t.Fatalf("серийник в базе %q, хочу %q", agent.CertSerial, cert.SerialNumber.String())
	}
	return out.CertPEM, cert.SerialNumber.String(), priv
}

// mintCert — сертификат напрямую ключом CA (мимо register): для
// просроченных и посторонних сценариев.
func mintCert(t *testing.T, ca *pki.CA, cn string, notBefore, notAfter time.Time, eku x509.ExtKeyUsage) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatalf("выпуск: %v", err)
	}
	return der, key
}

// enrollBody — JSON тела регистрации с заменами полей.
func enrollBody(t *testing.T, mutate func(*enrollRequest)) []byte {
	t.Helper()
	csrPEM, _ := newCSRPair(t, testCN)
	req := enrollRequest{Token: "любой-токен-придёт-из-фикстуры", CSRPEM: string(csrPEM), Hostname: "pc1"}
	if mutate != nil {
		mutate(&req)
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func auditActions(e *env) map[string]int {
	e.t.Helper()
	entries, err := audit.List(context.Background(), e.st.DB(), 0, 0)
	if err != nil {
		e.t.Fatalf("журнал: %v", err)
	}
	out := map[string]int{}
	for _, en := range entries {
		key := en.Action + "/" + en.Result
		out[key]++
	}
	return out
}
