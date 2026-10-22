// Package snmp — сбор данных с управляемых устройств по SNMP
// (только чтение): имя и описание системы, порты (ifName/ifDescr),
// таблица коммутации MAC → порт (Q-BRIDGE с запасным BRIDGE) и
// соседи LLDP.
//
// Границы безопасности: опрашиваются только цели, явно заданные
// исполнителем и прошедшие CheckTargets (адрес обязан быть внутри
// scope); операции — только Get и Walk; учётные данные приходят
// параметрами и никуда не пишутся. Каждый запрос берёт слот
// лимитера через NewLimitedWalker.
package snmp

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// Kind — тип значения SNMP-переменной в PDU.
type Kind byte

const (
	KindInt    Kind = iota + 1 // Value int64
	KindBytes                  // Value []byte (OctetString, Opaque, IPAddress)
	KindOID                    // Value string
	KindNoSuch                 // Value nil (NoSuchObject, NoSuchInstance, EndOfMibView, Null)
)

// PDU — одна переменная SNMP-ответа. Value интерпретируется по Kind.
type PDU struct {
	OID   string
	Kind  Kind
	Value any
}

// Walker — только чтение: Get по списку OID и Walk по поддереву.
// Реализации обязаны ограничивать каждый запрос дедлайном и повторами;
// контекст проверяется перед запросом.
type Walker interface {
	Get(ctx context.Context, oids ...string) ([]PDU, error)
	Walk(ctx context.Context, root string, fn func(PDU) error) error
	Close() error
}

// Scope — проверка границ цели (совместим с *scanner.Scope).
type Scope interface {
	Contains(netip.Addr) bool
}

// CheckTargets проверяет, что каждая цель внутри границ; иначе
// возвращает ошибку со списком отвергнутых адресов. Опрашивать можно
// только явно заданные адреса из scope — всю подсеть нельзя.
// nil-scope никого не пропускает (fail closed).
func CheckTargets(s Scope, targets []netip.Addr) error {
	rejected := make([]string, 0)
	for _, t := range targets {
		if s == nil || !s.Contains(t) {
			rejected = append(rejected, t.String())
		}
	}
	if len(rejected) > 0 {
		return fmt.Errorf("snmp: цели вне границ сканирования: %s (опрашивать можно только адреса из --subnets)", strings.Join(rejected, ", "))
	}
	return nil
}

// Limiter — ограничитель запросов: выдаёт слот на один SNMP-запрос.
// Совместим с *scanner.Limiter.
type Limiter interface {
	Acquire(ctx context.Context) (release func(), err error)
}

// LimitedWalker оборачивает Walker: каждый Get и Walk берёт слот
// лимитера перед выполнением и отпускает после ответа или ошибки,
// так что SNMP-запросы ограничены так же, как ping и имена.
type LimitedWalker struct {
	w       Walker
	limiter Limiter
}

// NewLimitedWalker связывает walker с ограничителем. nil-ограничитель
// делает каждый запрос ошибкой (fail closed, как в Sweep).
func NewLimitedWalker(w Walker, l Limiter) *LimitedWalker {
	return &LimitedWalker{w: w, limiter: l}
}

// Get выполняет один Get под слотом лимитера.
func (lw *LimitedWalker) Get(ctx context.Context, oids ...string) ([]PDU, error) {
	if lw.limiter == nil {
		return nil, fmt.Errorf("snmp: ограничитель не задан")
	}
	release, err := lw.limiter.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return lw.w.Get(ctx, oids...)
}

// Walk выполняет один обход под слотом лимитера.
func (lw *LimitedWalker) Walk(ctx context.Context, root string, fn func(PDU) error) error {
	if lw.limiter == nil {
		return fmt.Errorf("snmp: ограничитель не задан")
	}
	release, err := lw.limiter.Acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	return lw.w.Walk(ctx, root, fn)
}

// Close закрывает нижний walker (не сетевой запрос — без слота).
func (lw *LimitedWalker) Close() error { return lw.w.Close() }

// printableBytes переводит байты в строку, если они печатные ASCII;
// иначе hex-строка. Управляющие байты из ответов не печатаются.
func printableBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return "0x" + strings.ToUpper(fmt.Sprintf("%x", b))
		}
	}
	return string(b)
}

// pduBytes возвращает байты PDU, если Kind позволяет.
func pduBytes(p PDU) ([]byte, bool) {
	b, ok := p.Value.([]byte)
	return b, ok && p.Kind == KindBytes
}

// pduInt возвращает целое PDU, если Kind позволяет.
func pduInt(p PDU) (int, bool) {
	if p.Kind != KindInt {
		return 0, false
	}
	v, ok := p.Value.(int64)
	return int(v), ok
}

// macFromOIDParts форматирует компоненты OID как MAC-байты и
// нормализует через model.NormalizeMAC (тот же слой правил, что и в
// ARP: нулевые, широковещательные и групповые адреса отбрасываются).
func macFromOIDParts(parts []uint64) (string, bool) {
	if len(parts) != 6 {
		return "", false
	}
	raw := make([]byte, 6)
	for i, p := range parts {
		if p > 0xff {
			return "", false
		}
		raw[i] = byte(p)
	}
	const digits = "0123456789abcdef"
	s := make([]byte, 0, 17)
	for i, b := range raw {
		if i > 0 {
			s = append(s, ':')
		}
		s = append(s, digits[b>>4], digits[b&0x0f])
	}
	mac, err := model.NormalizeMAC(string(s))
	if err != nil {
		return "", false
	}
	return mac, true
}

// oidIndex разбирает суффикс OID после префикса в числа. false — OID
// не начинается с префикса или суффикс пуст/не числа.
func oidIndex(oid, prefix string) ([]uint64, bool) {
	suf, ok := strings.CutPrefix(oid, prefix)
	if !ok || suf == "" {
		return nil, false
	}
	suf = strings.TrimPrefix(suf, ".")
	if suf == "" {
		return nil, false
	}
	parts := strings.Split(suf, ".")
	out := make([]uint64, 0, len(parts))
	for _, p := range parts {
		n := uint64(0)
		if p == "" {
			return nil, false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return nil, false
			}
			n = n*10 + uint64(p[i]-'0')
		}
		out = append(out, n)
	}
	return out, true
}
