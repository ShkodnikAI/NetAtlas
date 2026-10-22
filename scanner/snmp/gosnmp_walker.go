package snmp

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	// RequestTimeout — дедлайн одного SNMP-запроса.
	RequestTimeout = 2 * time.Second
	// RequestRetries — число повторов одного запроса.
	RequestRetries = 2
	// SNMP-порт назначения.
	snmpPort = 161
)

// Auth — способ аутентификации SNMP. V2C включает community-строку
// (v2c разрешён только явно); иначе SNMPv3 authPriv: SHA для
// аутентификации и AES для шифрования. Значения приходят параметрами
// (в CLI — из переменных окружения) и никуда не пишутся.
type Auth struct {
	V2C       bool
	Community string
	User      string
	AuthPass  string
	PrivPass  string
}

// GoWalker — Walker поверх gosnmp для одной цели. Операции только
// Get и BulkWalk; каждый запрос ограничен RequestTimeout и повторяется
// до RequestRetries раз (ограничение gosnmp).
type GoWalker struct {
	g *gosnmp.GoSNMP
}

// NewGoWalker создаёт walker для одной цели и открывает UDP-сокет.
// Пустые учётные данные для выбранной версии — ошибка (текст без
// самих значений).
func NewGoWalker(target netip.Addr, a Auth) (*GoWalker, error) {
	if !target.IsValid() || !target.Is4() {
		return nil, fmt.Errorf("snmp: нужен валидный IPv4-адрес цели, получен %v", target)
	}
	g := &gosnmp.GoSNMP{
		Target:  target.String(),
		Port:    snmpPort,
		Timeout: RequestTimeout,
		Retries: RequestRetries,
	}
	if a.V2C {
		if a.Community == "" {
			return nil, fmt.Errorf("snmp: v2c: не задано сообщество")
		}
		g.Version = gosnmp.Version2c
		g.Community = a.Community
	} else {
		if a.User == "" || a.AuthPass == "" || a.PrivPass == "" {
			return nil, fmt.Errorf("snmp: v3: не заданы пользователь или пароли (SHA/AES)")
		}
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = gosnmp.AuthPriv
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 a.User,
			AuthenticationProtocol:   gosnmp.SHA,
			AuthenticationPassphrase: a.AuthPass,
			PrivacyProtocol:          gosnmp.AES,
			PrivacyPassphrase:        a.PrivPass,
		}
	}
	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("snmp: подключение к %s: %w", target, err)
	}
	return &GoWalker{g: g}, nil
}

// Get выполняет один Get-запрос по списку OID.
func (w *GoWalker) Get(ctx context.Context, oids ...string) ([]PDU, error) {
	if len(oids) == 0 {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	res, err := w.g.Get(oids)
	if err != nil {
		return nil, err
	}
	out := make([]PDU, 0, len(res.Variables))
	for _, v := range res.Variables {
		out = append(out, pduFromGoSNMP(v))
	}
	return out, nil
}

// Walk обходит поддерево GETBULK-запросами (v2c/v3).
func (w *GoWalker) Walk(ctx context.Context, root string, fn func(PDU) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return w.g.BulkWalk(root, func(v gosnmp.SnmpPDU) error {
		return fn(pduFromGoSNMP(v))
	})
}

// Close закрывает сокет.
func (w *GoWalker) Close() error {
	if w.g.Conn == nil {
		return nil
	}
	return w.g.Conn.Close()
}

// pduFromGoSNMP переводит переменную gosnmp в PDU пакета; неизвестные
// типы и исключения (NoSuchObject и др.) — KindNoSuch/KindBytes без
// паники.
func pduFromGoSNMP(v gosnmp.SnmpPDU) PDU {
	switch v.Type {
	case gosnmp.Integer:
		if n, ok := v.Value.(int); ok {
			return PDU{OID: v.Name, Kind: KindInt, Value: int64(n)}
		}
	case gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks:
		if n, ok := v.Value.(uint32); ok {
			return PDU{OID: v.Name, Kind: KindInt, Value: int64(n)}
		}
	case gosnmp.Counter64:
		if n, ok := v.Value.(uint64); ok {
			return PDU{OID: v.Name, Kind: KindInt, Value: int64(n)}
		}
	case gosnmp.OctetString, gosnmp.Opaque, gosnmp.IPAddress:
		if b, ok := v.Value.([]byte); ok {
			return PDU{OID: v.Name, Kind: KindBytes, Value: append([]byte(nil), b...)}
		}
	case gosnmp.ObjectIdentifier:
		if s, ok := v.Value.(string); ok {
			return PDU{OID: v.Name, Kind: KindOID, Value: s}
		}
	}
	return PDU{OID: v.Name, Kind: KindNoSuch, Value: nil}
}

// гарантируем, что GoWalker реализует Walker.
var _ Walker = (*GoWalker)(nil)
