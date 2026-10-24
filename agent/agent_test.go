// Тесты ядра агента (NR-006): регистрация против локального
// сервера (настоящий TLS на 127.0.0.1), сохранность токена, цикл
// опроса, очередь, растущие паузы.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/agent/collect"
	"github.com/ShkodnikAI/NetAtlas/agent/spool"
	"github.com/ShkodnikAI/NetAtlas/pki"
	"github.com/ShkodnikAI/NetAtlas/server/agentapi"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// startAgentServer — серверная сторона на локальных эфемерных
// портах: mTLS + enroll (как в NR-024).
type agentServer struct {
	base      string // https://адрес mTLS-слушателя (checkin, inventory)
	enrollURL string // https://адрес слушателя регистрации
	caPath    string // ca.pem каталога ключей сервера
	st        *store.Store
	issueTok  func() string
	stop      func()
}

func startAgentServer(t *testing.T) *agentServer {
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
	api, err := agentapi.New(st, ca, 2*time.Second)
	if err != nil {
		t.Fatalf("agentapi: %v", err)
	}
	api.SetRevocationTTL(time.Hour)
	certPEM, keyPEM, err := pki.EnsureServerCert(keyDir)
	if err != nil {
		t.Fatalf("EnsureServerCert: %v", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
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
	go func() { _ = agentapi.Serve(ctx, mLn, api.MTLSConfig(pair), api.MTLSHandler()) }()
	go func() { _ = agentapi.Serve(ctx, eLn, api.EnrollConfig(pair), api.EnrollHandler()) }()
	t.Cleanup(func() {
		cancel()
		st.Close()
	})
	return &agentServer{
		base:      "https://" + mLn.Addr().String(),
		enrollURL: "https://" + eLn.Addr().String(),
		caPath:    filepath.Join(keyDir, "ca.pem"),
		st:        st,
		issueTok:  func() string { tok, _ := st.IssueEnrollToken(context.Background(), "owner"); return tok },
		stop:      cancel,
	}
}

// Полный путь: enroll → файлы → checkin по mTLS. Токен не остаётся
// на диске.
func TestEnrollAndCheckin(t *testing.T) {
	srv := startAgentServer(t)
	dir := t.TempDir()
	caPath := copyCA(t, srv, dir)
	token := srv.issueTok()

	id, err := Enroll(context.Background(), srv.enrollURL, token, dir, caPath)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if !strings.HasPrefix(id, "agent:") {
		t.Fatalf("личность %q вне схемы agent:", id)
	}
	// Агент в хранилище активен.
	a, err := srv.st.AgentByID(context.Background(), id)
	if err != nil || a.Status != "active" {
		t.Fatalf("агент в базе: %+v (err %v)", a, err)
	}
	// Файлы: ключ, сертификат, CA; токена нигде нет (мутация M4).
	for name, want := range map[string]bool{keyFile: true, certFile: true, caFile: true} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil != want {
			t.Fatalf("файл %s: есть=%v, хочу %v", name, err == nil, want)
		}
	}
	assertTokenNotOnDisk(t, dir, token)

	// Клиент по сохранённому сертификату проходит mTLS-checkin.
	client, err := NewClient(srv.base, dir)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	check, err := client.Checkin(context.Background())
	if err != nil {
		t.Fatalf("checkin: %v", err)
	}
	if len(check.Jobs) != 0 {
		t.Fatalf("заданий быть не должно: %v", check.Jobs)
	}
}

func copyCA(t *testing.T, srv *agentServer, dir string) string {
	t.Helper()
	// Для регистрации агенту отдают файл ca.pem сервера (в жизни —
	// владелец); тест ссылается на каталог ключей сервера.
	return srv.caPath
}

// Чужой CA отвергается на регистрации (мутация M3 снимает проверку).
func TestEnrollForeignCARejected(t *testing.T) {
	srv := startAgentServer(t)
	foreignDir := t.TempDir()
	if err := pki.InitDir(foreignDir); err != nil {
		t.Fatalf("InitDir чужого CA: %v", err)
	}
	dir := t.TempDir()
	foreignCA := filepath.Join(foreignDir, "ca.pem")
	if _, err := Enroll(context.Background(), srv.enrollURL, srv.issueTok(), dir, foreignCA); err == nil {
		t.Fatal("регистрация с чужим CA прошла")
	}
}

// Плохой токен: регистрация отклонена, файлов сертификата нет.
func TestEnrollBadToken(t *testing.T) {
	srv := startAgentServer(t)
	dir := t.TempDir()
	caPath := copyCA(t, srv, dir)
	if _, err := Enroll(context.Background(), srv.enrollURL, "deadbeef", dir, caPath); err == nil {
		t.Fatal("плохой токен принят")
	}
	if _, err := os.Stat(filepath.Join(dir, certFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("сертификат записан при отказе")
	}
}

// Цикл RunOnce: спул при потере связи, слив по восстановлению,
// интервал из checkin.
type fakeTransport struct {
	checkins int
	sent     [][]byte
	metrics  [][]byte
	security [][]byte
	checkErr error
	sendErr  error
	secErr   error // отдельная ошибка для /agent/v1/security
	pollSec  int
}

func (f *fakeTransport) Checkin(ctx context.Context) (Checkin, error) {
	f.checkins++
	if f.checkErr != nil {
		return Checkin{}, f.checkErr
	}
	return Checkin{PollSec: f.pollSec}, nil
}

func (f *fakeTransport) SendInventory(ctx context.Context, body []byte) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, append([]byte(nil), body...))
	return nil
}

func (f *fakeTransport) SendMetrics(ctx context.Context, body []byte) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.metrics = append(f.metrics, append([]byte(nil), body...))
	return nil
}

func (f *fakeTransport) SendSecurity(ctx context.Context, body []byte) error {
	if f.secErr != nil {
		return f.secErr
	}
	if f.sendErr != nil {
		return f.sendErr
	}
	f.security = append(f.security, append([]byte(nil), body...))
	return nil
}

func okCollector() collect.Collector {
	return fixedCollector{name: collect.NameOS, raw: json.RawMessage(`{"caption":"Test OS","version":"1.0"}`)}
}

type fixedCollector struct {
	name string
	raw  json.RawMessage
	err  error
}

func (c fixedCollector) Name() string { return c.name }

func (c fixedCollector) Collect(ctx context.Context) (json.RawMessage, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.raw, nil
}

func newTestRunner(t *testing.T, tr Transport) *Runner {
	t.Helper()
	dir := t.TempDir()
	sp, err := spool.Open(SpoolDir(dir), spool.DefaultMaxBytes)
	if err != nil {
		t.Fatalf("spool: %v", err)
	}
	return &Runner{
		Interval:   time.Minute,
		Collectors: []collect.Collector{okCollector()},
		transport:  tr,
		spool:      sp,
		Now:        func() time.Time { return time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC) },
	}
}

func TestRunOnceSendAndSpool(t *testing.T) {
	tr := &fakeTransport{pollSec: 120}
	r := newTestRunner(t, tr)

	// Успешный цикл: отчёт ушёл, конверт версии 1 (мутация M8).
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(tr.sent) != 1 {
		t.Fatalf("отправок %d, хочу 1", len(tr.sent))
	}
	var env InventoryEnvelope
	if err := json.Unmarshal(tr.sent[0], &env); err != nil {
		t.Fatalf("конверт: %v", err)
	}
	if env.Kind != "inventory" || env.SchemaVer != collect.SchemaVersion {
		t.Fatalf("конверт: kind=%q schema=%d", env.Kind, env.SchemaVer)
	}
	var rep collect.Report
	if err := json.Unmarshal(env.Payload, &rep); err != nil {
		t.Fatalf("отчёт: %v", err)
	}
	if rep.InventorySchemaVersion != collect.SchemaVersion || rep.OS == nil || rep.OS.Caption != "Test OS" {
		t.Fatalf("отчёт: %+v", rep)
	}
	// Интервал обновился из checkin.
	if r.Interval != 120*time.Second {
		t.Fatalf("интервал %v, хочу 2m из checkin", r.Interval)
	}

	// Потеря связи после checkin: отчёт в очередь (мутация M1 — лимит).
	tr.sendErr = errors.New("сеть недоступна")
	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("цикл без ошибки при недоступной сети")
	}
	n, _ := r.spool.Len()
	if n != 1 {
		t.Fatalf("в очереди %d, хочу 1", n)
	}
	// Связь восстановлена: очередь сливается первой, порядок ФИФО.
	tr.sendErr = nil
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce после восстановления: %v", err)
	}
	if n, _ := r.spool.Len(); n != 0 {
		t.Fatalf("очередь не слилась: %d", n)
	}
	if len(tr.sent) != 3 {
		t.Fatalf("отправок %d, хочу 3 (из очереди и новый)", len(tr.sent))
	}
}

// Растущие паузы при ошибках подряд: base*2^k до предела 15 минут
// (мутация M2 снимает рост — паузы перестают расти).
func TestRunBackoffExponential(t *testing.T) {
	tr := &fakeTransport{checkErr: errors.New("сервер недоступен")}
	r := newTestRunner(t, tr)
	r.Interval = time.Minute
	r.backoffBase = 30 * time.Second
	r.backoffMax = 15 * time.Minute

	var pauses []time.Duration
	r.Sleep = func(ctx context.Context, d time.Duration) error {
		pauses = append(pauses, d)
		if len(pauses) >= 10 {
			return context.Canceled
		}
		return nil
	}
	_ = r.Run(context.Background())
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute,
		8 * time.Minute, 15 * time.Minute, 15 * time.Minute, 15 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	if len(pauses) != len(want) {
		t.Fatalf("пауз %d, хочу %d: %v", len(pauses), len(want), pauses)
	}
	for i, w := range want {
		if pauses[i] != w {
			t.Fatalf("пауза %d = %v, хочу %v", i, pauses[i], w)
		}
	}
}

// Сборщик с ошибкой не роняет цикл: отчёт с collector_errors уходит.
func TestRunOnceCollectorErrorStillSends(t *testing.T) {
	tr := &fakeTransport{}
	r := newTestRunner(t, tr)
	// Два сборщика: ошибочный и успешный.
	r.Collectors = []collect.Collector{
		fixedCollector{name: collect.NameDisks, err: errors.New("powershell недоступен")},
		okCollector(),
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("цикл упал из-за сборщика: %v", err)
	}
	var env InventoryEnvelope
	if err := json.Unmarshal(tr.sent[0], &env); err != nil {
		t.Fatalf("конверт: %v", err)
	}
	var rep collect.Report
	if err := json.Unmarshal(env.Payload, &rep); err != nil {
		t.Fatalf("отчёт: %v", err)
	}
	if len(rep.CollectorErrors) != 1 || rep.Disks != nil || rep.OS == nil {
		t.Fatalf("ошибки сборщика: %+v", rep)
	}
}

// Агент (включая сборщики и очередь) не открывает слушающих
// сокетов: grep-проверка исходников (наряд требует именно такой
// тест). Комментарий с "net.Listen(" тоже ловится (мутация M7).
func TestAgentSourceOpensNoListeners(t *testing.T) {
	forbidden := []string{"net.Listen(", "ListenAndServe("}
	roots := []string{".", filepath.Join("..", "cmd", "netatlas-agent")}
	var checked int
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			checked++
			for _, f := range forbidden {
				if bytes.Contains(data, []byte(f)) {
					return fmt.Errorf("%s содержит %q — агент не имеет права слушать", path, f)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 8 {
		t.Fatalf("проверено файлов %d — подозрительно мало", checked)
	}
}

// Токен не попадает ни в один файл каталога состояния.
func assertTokenNotOnDisk(t *testing.T, dir, token string) {
	t.Helper()
	if token == "" {
		t.Fatal("токен фикстуры пуст")
	}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(token)) {
			return fmt.Errorf("токен регистрации сохранён в %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
