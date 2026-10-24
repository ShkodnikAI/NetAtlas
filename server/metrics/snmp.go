// SNMP-задача сервера (NR-008): чтение счётчиков портов
// коммутаторов (только чтение, внутри Scope, через Limiter) и
// расчёт загрузки порта по разности счётчиков с учётом
// переполнения. Цели и учётные данные задаёт владелец; по умолчанию
// задача выключена.
package metrics

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/scanner/snmp"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// OID-ы IF-MIB (только чтение).
const (
	oidIfInOctets   = "1.3.6.1.2.1.2.2.1.10"
	oidIfOutOctets  = "1.3.6.1.2.1.2.2.1.16"
	oidIfInErrors   = "1.3.6.1.2.1.2.2.1.14"
	oidIfOutErrors  = "1.3.6.1.2.1.2.2.1.20"
	oidIfInDiscards = "1.3.6.1.2.1.2.2.1.13"
	oidIfHighSpeed  = "1.3.6.1.2.1.31.1.1.1.15"
)

// counter32max — граница 32-битного счётчика (переполнение).
const counter32max = 1 << 32

// pollInterval — частота опроса целей.
const pollInterval = 5 * time.Minute

// Task — фоновый сбор SNMP-счётчиков.
type Task struct {
	Targets   []netip.Addr
	Auth      snmp.Auth
	Scope     *scanner.Scope
	Store     *store.Store
	NewWalker func(target netip.Addr, auth snmp.Auth) (snmp.Walker, error)

	mu    sync.Mutex
	prev  map[string]snmpPoint // "target:ifIndex" → прошлое значение
	prevT time.Time
}

// snmpPoint — снимок счётчиков одного порта.
type snmpPoint struct {
	in, out, inErr, outErr, inDisc, speed float64
}

// NewTask — задача; цели внутри Scope проверяются сразу.
func NewTask(targets []netip.Addr, auth snmp.Auth, sc *scanner.Scope, st *store.Store) (*Task, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	if sc == nil {
		return nil, fmt.Errorf("metrics: --snmp-targets без --subnets: границы не заданы")
	}
	for _, t := range targets {
		if !sc.Contains(t) {
			return nil, fmt.Errorf("metrics: цель %s вне подсетей --subnets", t)
		}
	}
	return &Task{
		Targets: targets, Auth: auth, Scope: sc, Store: st,
		NewWalker: func(target netip.Addr, a snmp.Auth) (snmp.Walker, error) {
			return snmp.NewGoWalker(target, a)
		},
		prev: map[string]snmpPoint{},
	}, nil
}

// RunOnce — один опрос всех целей: счётчики → разности → метрики.
func (t *Task) RunOnce(ctx context.Context) error {
	now := time.Now()
	for _, target := range t.Targets {
		if err := t.poll(ctx, target, now); err != nil {
			log.Printf("metrics: snmp %s: %v", target, err)
		}
	}
	return nil
}

// poll — чтение и разности одной цели.
func (t *Task) poll(ctx context.Context, target netip.Addr, now time.Time) error {
	w, err := t.NewWalker(target, t.Auth)
	if err != nil {
		return err
	}
	defer w.Close()

	// Порт: ifIndex → снимок (ходим по поддеревьям и связываем индексы).
	ports := map[int]*snmpPoint{}
	read := func(oid string, set func(p *snmpPoint, v float64)) error {
		return w.Walk(ctx, oid, func(pdu snmp.PDU) error {
			// Имя OID: ...1.3.6.1.2.1.2.2.1.10.<ifIndex>
			suffix := pdu.OID
			if len(suffix) > len(oid)+1 {
				idx, err := strconv.Atoi(suffix[len(oid)+1:])
				if err != nil {
					return nil
				}
				p := ports[idx]
				if p == nil {
					p = &snmpPoint{}
					ports[idx] = p
				}
				set(p, pduToF(pdu))
			}
			return nil
		})
	}
	if err := read(oidIfInOctets, func(p *snmpPoint, v float64) { p.in = v }); err != nil {
		return err
	}
	if err := read(oidIfOutOctets, func(p *snmpPoint, v float64) { p.out = v }); err != nil {
		return err
	}
	if err := read(oidIfInErrors, func(p *snmpPoint, v float64) { p.inErr = v }); err != nil {
		return err
	}
	if err := read(oidIfOutErrors, func(p *snmpPoint, v float64) { p.outErr = v }); err != nil {
		return err
	}
	if err := read(oidIfInDiscards, func(p *snmpPoint, v float64) { p.inDisc = v }); err != nil {
		return err
	}
	if err := read(oidIfHighSpeed, func(p *snmpPoint, v float64) { p.speed = v }); err != nil {
		return err
	}

	targetStr := target.String()
	samples := []store.MetricSample{}
	t.mu.Lock()
	defer t.mu.Unlock()
	dt := pollInterval
	if !t.prevT.IsZero() {
		dt = now.Sub(t.prevT)
	}
	for idx, cur := range ports {
		key := targetStr + ":" + strconv.Itoa(idx)
		prev, ok := t.prev[key]
		t.prev[key] = *cur
		if !ok || cur.speed <= 0 {
			continue // первая точка — только база для разностей
		}
		linkBps := cur.speed * 1e6 // ifHighSpeed в Мбит/с
		if linkBps <= 0 {
			continue
		}
		in := counterDelta(prev.in, cur.in)
		out := counterDelta(prev.out, cur.out)
		util := (in + out) * 8 / dt.Seconds() / linkBps * 100
		samples = append(samples,
			store.MetricSample{AgentID: "snmp:" + targetStr, Target: "port:" + strconv.Itoa(idx), Kind: "port_util", Value: util, At: now},
		)
		if e := counterDelta(prev.inErr+prev.outErr, cur.inErr+cur.outErr); e > 0 {
			samples = append(samples, store.MetricSample{AgentID: "snmp:" + targetStr, Target: "port:" + strconv.Itoa(idx), Kind: "port_errors", Value: e, At: now})
		}
		if d := counterDelta(prev.inDisc, cur.inDisc); d > 0 {
			samples = append(samples, store.MetricSample{AgentID: "snmp:" + targetStr, Target: "port:" + strconv.Itoa(idx), Kind: "port_discards", Value: d, At: now})
		}
	}
	t.prevT = now
	if len(samples) > 0 {
		return t.Store.SaveMetricsRaw(ctx, samples)
	}
	return nil
}

// counterDelta — разность счётчика с учётом переполнения 32 бит.
func counterDelta(prev, cur float64) float64 {
	if cur < prev {
		return (counter32max - prev) + cur
	}
	return cur - prev
}

// pduToF — значение PDU в число (не число — 0).
func pduToF(pdu snmp.PDU) float64 {
	switch v := pdu.Value.(type) {
	case int64:
		return float64(v)
	case uint64:
		return float64(v)
	case uint32:
		return float64(v)
	}
	return 0
}

// Loop — фоновый цикл до остановки контекста.
func (t *Task) Loop(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	// Первая точка — сразу (база для разностей).
	if err := t.RunOnce(ctx); err != nil {
		log.Printf("metrics: snmp: %v", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := t.RunOnce(ctx); err != nil {
				log.Printf("metrics: snmp: %v", err)
			}
		}
	}
}
