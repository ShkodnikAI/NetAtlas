//go:build windows

// ICMP на Windows: системный вызов IcmpSendEcho (iphlpapi.dll) —
// права администратора не нужны (аудитор NR-008).
package measure

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreate   = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose    = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho = iphlpapi.NewProc("IcmpSendEcho")
)

// echoReply — ICMP_ECHO_REPLY (32-битная структура iphlpapi).
type echoReply struct {
	Address   uint32
	Status    uint32
	RoundTrip uint32
	DataSize  uint16
	Reserved  uint16
}

// windowsProber — пул дескрипторов IcmpCreateFile (по горутине не
// нужно: IcmpSendEcho синхронный).
type windowsProber struct {
	mu   sync.Mutex
	h    uintptr
	addr map[string]uint32
}

// NewProber — реальный пробер Windows.
func NewProber() (*windowsProber, error) {
	h, _, err := procIcmpCreate.Call()
	if h == 0 || h == uintptr(^uintptr(0)) {
		return nil, fmt.Errorf("measure: IcmpCreateFile: %v", err)
	}
	return &windowsProber{h: h, addr: map[string]uint32{}}, nil
}

// Close закрывает дескриптор.
func (p *windowsProber) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.h != 0 {
		procIcmpClose.Call(p.h)
		p.h = 0
	}
	return nil
}

// resolveAddr — адрес в сетевом порядке байт (кэш на адрес).
func (p *windowsProber) resolveAddr(host string) (uint32, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if v, ok := p.addr[host]; ok {
		return v, nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return 0, fmt.Errorf("measure: адрес %s: %v", host, err)
		}
		ip = ips[0]
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, fmt.Errorf("measure: %s не IPv4", host)
	}
	v := binary.BigEndian.Uint32(v4)
	p.addr[host] = v
	return v, nil
}

// Ping — одна серия из attempts эхо по 32 байта, таймаут 1 секунда.
func (p *windowsProber) Ping(ctx context.Context, host string, attempts int) ([]float64, error) {
	dst, err := p.resolveAddr(host)
	if err != nil {
		return nil, err
	}
	out := make([]float64, 0, attempts)
	payload := make([]byte, 32) // нулевое тело эхо
	ipOptSize := 0
	replySize := unsafe.Sizeof(echoReply{}) + uintptr(len(payload)) + 8
	buf := make([]byte, replySize)
	for i := 0; i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			return out, nil
		}
		p.mu.Lock()
		ret, _, _ := procIcmpSendEcho.Call(
			p.h,
			uintptr(dst),
			uintptr(unsafe.Pointer(&payload[0])),
			uintptr(len(payload)),
			uintptr(ipOptSize),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			1000, // таймаут, мс
		)
		p.mu.Unlock()
		if ret == 0 {
			out = append(out, -1) // потеря
			continue
		}
		count := *(*uint32)(unsafe.Pointer(&buf[0]))
		if count == 0 {
			out = append(out, -1)
			continue
		}
		reply := (*echoReply)(unsafe.Pointer(&buf[8]))
		if reply.Status != 0 {
			out = append(out, -1)
			continue
		}
		out = append(out, float64(reply.RoundTrip))
	}
	return out, nil
}
