package names

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// Порты и адреса источников имён. NBPort и MDNSPort — unicast-порты
// на целевом хосте; SSDP — фиксированная multicast-группа.
const (
	NBPort   = 137
	MDNSPort = 5353

	// NBTimeout — дедлайн ожидания NBNS-ответа.
	NBTimeout = 2 * time.Second
	// MDNSTimeout — дедлайн ожидания mDNS-ответа.
	MDNSTimeout = 2 * time.Second
	// SSDPWindow — окно сбора SSDP-ответов.
	SSDPWindow = 3 * time.Second
)

// Client — клиент разрешения имён поверх одного UDP-сокета.
// Проверку границ (scope) выполняет вызывающая сторона: unicast-запросы
// клиент отправляет только по указанному адресу, а фильтрацию SSDP-ответов
// по scope делает интеграция (scanner).
type Client struct {
	conn   net.PacketConn
	nextID atomic.Uint32
	closed atomic.Bool

	// Таймауты выставляются в NewClient; в тестах их можно уменьшить.
	NBTimeout   time.Duration
	MDNSTimeout time.Duration
	SSDPWindow  time.Duration
}

// NewClient создаёт клиент поверх готового UDP-сокета.
func NewClient(conn net.PacketConn) *Client {
	return &Client{
		conn:        conn,
		NBTimeout:   NBTimeout,
		MDNSTimeout: MDNSTimeout,
		SSDPWindow:  SSDPWindow,
	}
}

// Close закрывает сокет. Повторный вызов вернёт ошибку.
func (c *Client) Close() error {
	if c.closed.Swap(true) {
		return fmt.Errorf("names: клиент уже закрыт")
	}
	return c.conn.Close()
}

// nextTRN выдаёт следующий уникальный TRN ID (случайное зерно + счётчик).
func (c *Client) nextTRN() uint16 {
	return uint16(rand.Intn(1<<16)) + uint16(c.nextID.Add(1)&0xffff)
}

// udpAddr готовит адрес назначения для IPv4.
func udpAddr(ip netip.Addr, port int) *net.UDPAddr {
	b4 := ip.As4()
	return &net.UDPAddr{IP: net.IP(b4[:]), Port: port}
}

// srcAddr извлекает адрес отправителя пакета.
func srcAddr(a net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch v := a.(type) {
	case *net.UDPAddr:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	default:
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	return addr, addr.Is4()
}

// send пишет пакет по назначению.
func (c *Client) send(b []byte, addr *net.UDPAddr) error {
	if _, err := c.conn.WriteTo(b, addr); err != nil {
		return fmt.Errorf("names: отправка: %w", err)
	}
	return nil
}

// now возвращает текущее время.
func (c *Client) now() time.Time {
	return time.Now()
}

// readUntil читает пакеты до дедлайна, передавая каждый в handle;
// handle возвращает true — чтение завершено успешно, false — пакет
// не подошёл и чтение продолжается. Ошибка дедлайна — не ошибка
// источника (тишина), остальные ошибки возвращаются.
func (c *Client) readUntil(ctx context.Context, timeout time.Duration, handle func(data []byte, from netip.Addr) bool) (bool, error) {
	deadline := c.now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	buf := make([]byte, 2048)
	for {
		remaining := deadline.Sub(c.now())
		if remaining <= 0 {
			return false, nil
		}
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return false, fmt.Errorf("names: дедлайн чтения: %w", err)
		}
		n, from, err := c.conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return false, nil
			}
			if c.closed.Load() {
				return false, fmt.Errorf("names: сокет закрыт: %w", err)
			}
			return false, fmt.Errorf("names: чтение: %w", err)
		}
		src, ok := srcAddr(from)
		if !ok {
			continue
		}
		if handle(append([]byte(nil), buf[:n]...), src) {
			return true, nil
		}
	}
}

// NetBIOSName спрашивает имя по NBSTAT (Node Status, UDP/137 — аналог
// nbtstat -A): ответ принимается только от адреса назначения и только
// со своим TRN ID. Возвращается первое имя таблицы. Тишина — false, nil.
func (c *Client) NetBIOSName(ctx context.Context, ip netip.Addr) (string, bool, error) {
	if !ip.IsValid() || !ip.Is4() {
		return "", false, fmt.Errorf("names: netbios: нужен валидный IPv4-адрес, получен %v", ip)
	}
	trn := c.nextTRN()
	query, err := EncodeNodeStatusQuery(trn)
	if err != nil {
		return "", false, fmt.Errorf("names: netbios: %w", err)
	}
	if err := c.send(query, udpAddr(ip, NBPort)); err != nil {
		return "", false, err
	}
	var name string
	found, err := c.readUntil(ctx, c.NBTimeout, func(data []byte, from netip.Addr) bool {
		if from != ip {
			return false // ответ принимается только от адреса назначения
		}
		names, err := DecodeNodeStatusResponse(data, trn)
		if err != nil || len(names) == 0 {
			return false
		}
		name = names[0]
		return true
	})
	if err != nil || !found {
		return "", false, err
	}
	return name, true, nil
}

// MDNSName спрашивает имя по mDNS (UDP/5353) обратным PTR-запросом:
// ответ принимается только от адреса назначения. Тишина — false, nil.
func (c *Client) MDNSName(ctx context.Context, ip netip.Addr) (string, bool, error) {
	if !ip.IsValid() || !ip.Is4() {
		return "", false, fmt.Errorf("names: mdns: нужен валидный IPv4-адрес, получен %v", ip)
	}
	trn := c.nextTRN()
	query, err := EncodeReverseQuery(ip, trn)
	if err != nil {
		return "", false, fmt.Errorf("names: mdns: %w", err)
	}
	if err := c.send(query, udpAddr(ip, MDNSPort)); err != nil {
		return "", false, err
	}
	var name string
	found, err := c.readUntil(ctx, c.MDNSTimeout, func(data []byte, from netip.Addr) bool {
		if from != ip {
			return false
		}
		records, err := DecodeDNSResponse(data, trn)
		if err != nil {
			return false
		}
		n, ok := HostnameFromPTR(records)
		if !ok {
			return false
		}
		name = n
		return true
	})
	if err != nil || !found {
		return "", false, err
	}
	return name, true, nil
}

// SSDP рассылает один M-SEARCH в multicast-группу и собирает ответы
// в течение окна. Повторный ответ от того же адреса игнорируется —
// первый выигрывает. Фильтрацию по scope выполняет вызывающая сторона.
func (c *Client) SSDP(ctx context.Context) (map[netip.Addr]SSDPInfo, error) {
	group, err := netip.ParseAddr(SSDPGroup)
	if err != nil {
		return nil, fmt.Errorf("names: ssdp: %w", err)
	}
	if err := c.send(MSearch(), udpAddr(group, SSDPPort)); err != nil {
		return nil, err
	}
	out := make(map[netip.Addr]SSDPInfo)
	_, err = c.readUntil(ctx, c.SSDPWindow, func(data []byte, from netip.Addr) bool {
		if _, dup := out[from]; dup {
			return false // первый ответ от адреса выигрывает
		}
		info, err := ParseResponse(data, from)
		if err != nil {
			return false
		}
		out[from] = info
		return false // читаем до конца окна
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
