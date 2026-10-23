// Тесты подписи заданий (NR-007): детерминированное кодирование,
// подпись/проверка, секреты не попадают в JSON.

package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testEnv(t *testing.T) (Envelope, []byte) {
	t.Helper()
	content := []byte("робот: пропингуй 10.0.0.0/24")
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	now := time.Now()
	env := Envelope{
		JobID:         "job-1",
		AgentID:       "agent-77",
		Kind:          "ping-sweep",
		ContentSHA256: HashContent(content),
		IssuedAt:      now,
		ExpiresAt:     now.Add(time.Hour),
		Nonce:         nonce,
	}
	return env, content
}

// Кодирование детерминировано: перестановка полей структуры и разные
// зоны времени не меняют байты.
func TestEncodeDeterministic(t *testing.T) {
	env, _ := testEnv(t)
	a, err := env.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	b, err := env.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if string(a) != string(b) {
		t.Fatal("кодирование не детерминировано")
	}
	// Чужая зона с тем же моментом — те же байты.
	loc := time.FixedZone("TEST", 3*3600)
	env2 := env
	env2.IssuedAt = env.IssuedAt.In(loc)
	env2.ExpiresAt = env.ExpiresAt.In(loc)
	c, err := env2.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if string(a) != string(c) {
		t.Fatal("кодирование зависит от зоны времени")
	}
}

// Sign → проверка ed25519 тем же ключом сходится; чужой ключ — нет.
func TestSignAndVerifyRoundtrip(t *testing.T) {
	env, _ := testEnv(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	sj, err := Sign(env, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := env.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !ed25519.Verify(pub, data, sj.Signature) {
		t.Fatal("подпись не сходится с открытым ключом")
	}
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = otherPriv
	if ed25519.Verify(otherPub, data, sj.Signature) {
		t.Fatal("чужой ключ принял подпись")
	}
}

// Конверт с неверными размерами полей отвергается.
func TestSignRejectsBadEnvelope(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	env, _ := testEnv(t)
	env.ContentSHA256 = env.ContentSHA256[:8]
	if _, err := Sign(env, priv); err == nil {
		t.Fatal("короткий хэш принят")
	}
	env2, _ := testEnv(t)
	env2.Nonce = nil
	if _, err := Sign(env2, priv); err == nil {
		t.Fatal("пустой nonce принят")
	}
	env3, _ := testEnv(t)
	env3.ExpiresAt = env3.IssuedAt.Add(-time.Minute)
	if _, err := Sign(env3, priv); err == nil {
		t.Fatal("expires_at раньше issued_at принят")
	}
}

// JSON подписанного задания и сообщения об ошибках не содержат
// байтов закрытого ключа (секреты не попадают в ответы и логи).
func TestJSONNoPrivateKeyLeak(t *testing.T) {
	env, _ := testEnv(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	_ = pub
	sj, err := Sign(env, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, err := json.Marshal(sj)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	privHex := priv.Seed()
	for i := 0; i+8 <= len(privHex); i += 8 {
		if strings.Contains(string(raw), string(privHex[i:i+8])) {
			t.Fatal("байты закрытого ключа найдены в JSON задания")
		}
	}
	// Ошибки Sign не содержат материала ключа.
	_, err = Sign(Envelope{}, priv)
	if err == nil {
		t.Fatal("пустой конверт принят")
	}
	for i := 0; i+8 <= len(privHex); i += 8 {
		if strings.Contains(err.Error(), string(privHex[i:i+8])) {
			t.Fatal("байты закрытого ключа найдены в ошибке")
		}
	}
}
