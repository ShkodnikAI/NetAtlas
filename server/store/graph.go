package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// NodeInfo — узел графа с признаками ручного элемента и проверки.
type NodeInfo struct {
	model.Node
	Class    string `json:"class,omitempty"`
	Manual   bool   `json:"manual"`
	Verified bool   `json:"verified"`
}

// LinkInfo — связь графа с признаками ручной связи и проверки.
type LinkInfo struct {
	model.Link
	Manual   bool `json:"manual"`
	Verified bool `json:"verified"`
}

// Graph — карта сети целиком: узлы по ID, связи по (A, APort, B, BPort).
type Graph struct {
	Nodes []NodeInfo `json:"nodes"`
	Links []LinkInfo `json:"links"`
}

// Topology собирает граф из хранилища: устройства (включая ручные),
// связи, плюс узлы для концов связей, которые устройствами не
// являются (коммутаторы, виденные только по IP, «облака» и unknown-
// соседи). Результат детерминирован: сортировка как в model.Topology.
func (s *Store) Topology(ctx context.Context) (Graph, error) {
	g := Graph{Nodes: []NodeInfo{}, Links: []LinkInfo{}}

	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, class, label, hostname, manual, verified,
                (SELECT name FROM device_names WHERE device_id = devices.id ORDER BY seen ASC LIMIT 1)
                FROM devices ORDER BY id`)
	if err != nil {
		return g, fmt.Errorf("store: устройства: %w", err)
	}
	known := map[string]bool{}
	for rows.Next() {
		var id, kind, class, label, hostname string
		var manual, verified bool
		var name sql.NullString
		if err := rows.Scan(&id, &kind, &class, &label, &hostname, &manual, &verified, &name); err != nil {
			rows.Close()
			return g, fmt.Errorf("store: устройство: %w", err)
		}
		known[id] = true
		g.Nodes = append(g.Nodes, NodeInfo{
			Node:     model.Node{ID: id, Kind: kind, Label: nodeLabel(id, label, hostname, name.String)},
			Class:    class,
			Manual:   manual,
			Verified: verified,
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return g, fmt.Errorf("store: устройства: %w", err)
	}
	rows.Close()

	rows, err = s.db.QueryContext(ctx,
		`SELECT id, a, a_port, b, b_port, source, manual, verified FROM links`)
	if err != nil {
		return g, fmt.Errorf("store: связи: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, a, aPort, b, bPort, source string
		var manual, verified bool
		if err := rows.Scan(&id, &a, &aPort, &b, &bPort, &source, &manual, &verified); err != nil {
			return g, fmt.Errorf("store: связь: %w", err)
		}
		for _, end := range []string{a, b} {
			if known[end] {
				continue
			}
			known[end] = true
			g.Nodes = append(g.Nodes, extraNode(end))
		}
		g.Links = append(g.Links, LinkInfo{
			Link:     model.Link{A: a, APort: aPort, B: b, BPort: bPort, Source: source},
			Manual:   manual,
			Verified: verified,
		})
	}
	if err := rows.Err(); err != nil {
		return g, fmt.Errorf("store: связи: %w", err)
	}

	sortNodes(g.Nodes)
	sortLinks(g.Links)
	return g, nil
}

// nodeLabel — подпись устройства: ручное имя, hostname, первое имя,
// иначе идентификатор.
func nodeLabel(id, label, hostname, firstName string) string {
	switch {
	case label != "":
		return label
	case hostname != "":
		return hostname
	case firstName != "":
		return firstName
	}
	return id
}

// extraNode — узел для конца связи, которого нет среди устройств:
// «облако» неуправляемого коммутатора, коммутатор, виденный только по
// IP, или MAC-сосед без данных.
func extraNode(id string) NodeInfo {
	switch {
	case strings.HasPrefix(id, "cloud:"):
		port := id
		if i := strings.LastIndex(id, ":"); i >= 0 {
			port = id[i+1:]
		}
		return NodeInfo{Node: model.Node{ID: id, Kind: model.NodeKindCloud,
			Label: "неуправляемая сеть (" + port + ")"}}
	case strings.HasPrefix(id, "ip:"):
		return NodeInfo{Node: model.Node{ID: id, Kind: model.NodeKindSwitch,
			Label: strings.TrimPrefix(id, "ip:")}}
	default:
		return NodeInfo{Node: model.Node{ID: id, Kind: model.NodeKindUnknown, Label: id}}
	}
}

func sortNodes(nodes []NodeInfo) {
	for i := 1; i < len(nodes); i++ {
		for j := i; j > 0 && nodes[j].ID < nodes[j-1].ID; j-- {
			nodes[j], nodes[j-1] = nodes[j-1], nodes[j]
		}
	}
}

func sortLinks(links []LinkInfo) {
	less := func(x, y LinkInfo) bool {
		if x.A != y.A {
			return x.A < y.A
		}
		if x.APort != y.APort {
			return x.APort < y.APort
		}
		if x.B != y.B {
			return x.B < y.B
		}
		return x.BPort < y.BPort
	}
	for i := 1; i < len(links); i++ {
		for j := i; j > 0 && less(links[j], links[j-1]); j-- {
			links[j], links[j-1] = links[j-1], links[j]
		}
	}
}

// ListDevicesByClass возвращает устройства одного класса (для экрана
// «Найденные устройства»); класс валидируется.
func (s *Store) ListDevicesByClass(ctx context.Context, class model.Class) ([]DeviceInfo, error) {
	if !class.Valid() {
		return nil, fmt.Errorf("store: недопустимый класс устройства %q", string(class))
	}
	all, err := s.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	out := []DeviceInfo{}
	for _, d := range all {
		if d.Class == class {
			out = append(out, d)
		}
	}
	return out, nil
}

// DeviceInfo — карточка устройства с признаками ручного элемента и
// проверки.
type DeviceInfo struct {
	model.Device
	Manual   bool `json:"manual"`
	Verified bool `json:"verified"`
}

// Device возвращает карточку устройства: имена, IP, производитель,
// SSID, класс, наблюдения.
func (s *Store) Device(ctx context.Context, id string) (DeviceInfo, error) {
	var info DeviceInfo
	var class, kind string
	var seen, lastSeen string
	var vendor, ssid, label, hostname string
	err := s.db.QueryRowContext(ctx, `SELECT id, kind, class, label, hostname, vendor, ssid,
                manual, verified, first_seen, last_seen FROM devices WHERE id = ?`, id).
		Scan(&info.ID, &kind, &class, &label, &hostname, &vendor, &ssid, &info.Manual, &info.Verified, &seen, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceInfo{}, ErrNotFound
	}
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("store: устройство %s: %w", id, err)
	}
	info.MAC = info.ID
	info.Class = model.Class(class)
	if hostname != "" {
		info.Hostname = hostname
	}
	if vendor != "" {
		info.Vendor = vendor
	}
	if ssid != "" {
		info.SSID = ssid
	}
	info.IPs = []netip.Addr{}
	info.Names = []model.Name{}
	info.Observations = []model.Observation{}

	rows, err := s.db.QueryContext(ctx,
		`SELECT ip FROM device_ips WHERE device_id = ? ORDER BY ip`, id)
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("store: адреса устройства %s: %w", id, err)
	}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return DeviceInfo{}, fmt.Errorf("store: адрес устройства %s: %w", id, err)
		}
		a, err := netip.ParseAddr(raw)
		if err != nil {
			rows.Close()
			return DeviceInfo{}, fmt.Errorf("store: адрес устройства %s: %q: %w", id, raw, err)
		}
		info.IPs = append(info.IPs, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return DeviceInfo{}, fmt.Errorf("store: адреса устройства %s: %w", id, err)
	}

	rows, err = s.db.QueryContext(ctx,
		`SELECT source, name, seen FROM device_names WHERE device_id = ? ORDER BY seen ASC`, id)
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("store: имена устройства %s: %w", id, err)
	}
	for rows.Next() {
		var source, name, t string
		if err := rows.Scan(&source, &name, &t); err != nil {
			rows.Close()
			return DeviceInfo{}, fmt.Errorf("store: имя устройства %s: %w", id, err)
		}
		seenAt, err := time.Parse(time.RFC3339Nano, t)
		if err != nil {
			rows.Close()
			return DeviceInfo{}, fmt.Errorf("store: время имени устройства %s: %w", id, err)
		}
		info.Names = append(info.Names, model.Name{Source: source, Name: name, Seen: seenAt})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return DeviceInfo{}, fmt.Errorf("store: имена устройства %s: %w", id, err)
	}

	rows, err = s.db.QueryContext(ctx,
		`SELECT source, seen FROM observations WHERE device_id = ? ORDER BY source`, id)
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("store: наблюдения устройства %s: %w", id, err)
	}
	for rows.Next() {
		var source, t string
		if err := rows.Scan(&source, &t); err != nil {
			rows.Close()
			return DeviceInfo{}, fmt.Errorf("store: наблюдение устройства %s: %w", id, err)
		}
		seenAt, err := time.Parse(time.RFC3339Nano, t)
		if err != nil {
			rows.Close()
			return DeviceInfo{}, fmt.Errorf("store: время наблюдения устройства %s: %w", id, err)
		}
		info.Observations = append(info.Observations, model.Observation{Source: source, Seen: seenAt})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return DeviceInfo{}, fmt.Errorf("store: наблюдения устройства %s: %w", id, err)
	}
	return info, nil
}

// ListDevices возвращает все устройства (для экранов и классификации):
// карточки с классом, признаками, адресами, именами и наблюдениями.
// Данные собираются двумя-тремя выборками по всем устройствам и
// раскладываются в памяти — без запроса на каждое устройство.
func (s *Store) ListDevices(ctx context.Context) ([]DeviceInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, class, hostname, vendor, ssid,
		manual, verified, last_seen FROM devices ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: список устройств: %w", err)
	}
	out := []DeviceInfo{}
	idx := make(map[string]int)
	for rows.Next() {
		var info DeviceInfo
		var class, hostname, vendor, ssid, lastSeen string
		if err := rows.Scan(&info.ID, &class, &hostname, &vendor, &ssid,
			&info.Manual, &info.Verified, &lastSeen); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: устройство в списке: %w", err)
		}
		info.MAC = info.ID
		info.Class = model.Class(class)
		// Срезы пустые, не nil: в JSON должны быть [], а не null —
		// интерфейс вызывает .join по ним без проверок (смок NR-023).
		info.IPs = []netip.Addr{}
		info.Names = []model.Name{}
		info.Observations = []model.Observation{}
		if hostname != "" {
			info.Hostname = hostname
		}
		if vendor != "" {
			info.Vendor = vendor
		}
		if ssid != "" {
			info.SSID = ssid
		}
		idx[info.ID] = len(out)
		out = append(out, info)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: список устройств: %w", err)
	}

	// Адреса всех устройств одной выборкой (NR-030), порядок как в
	// одиночной Device(): по возрастанию адреса.
	rows, err = s.db.QueryContext(ctx, `SELECT device_id, ip FROM device_ips ORDER BY device_id, ip`)
	if err != nil {
		return nil, fmt.Errorf("store: адреса устройств: %w", err)
	}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: адрес устройства в списке: %w", err)
		}
		i, ok := idx[id]
		if !ok {
			continue // устройство удалено между выборками; FK не пускает
		}
		a, err := netip.ParseAddr(raw)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: адрес устройства %s: %q: %w", id, raw, err)
		}
		out[i].IPs = append(out[i].IPs, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: адреса устройств: %w", err)
	}

	// Имена всех устройств одной выборкой, порядок как в Device():
	// по времени появления.
	rows, err = s.db.QueryContext(ctx, `SELECT device_id, source, name, seen FROM device_names ORDER BY device_id, seen`)
	if err != nil {
		return nil, fmt.Errorf("store: имена устройств: %w", err)
	}
	for rows.Next() {
		var id, source, name, t string
		if err := rows.Scan(&id, &source, &name, &t); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: имя устройства в списке: %w", err)
		}
		i, ok := idx[id]
		if !ok {
			continue
		}
		seenAt, err := time.Parse(time.RFC3339Nano, t)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: время имени устройства %s: %w", id, err)
		}
		out[i].Names = append(out[i].Names, model.Name{Source: source, Name: name, Seen: seenAt})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: имена устройств: %w", err)
	}

	// Наблюдения всех устройств одной выборкой, порядок как в
	// Device(): по источнику.
	rows, err = s.db.QueryContext(ctx, `SELECT device_id, source, seen FROM observations ORDER BY device_id, source`)
	if err != nil {
		return nil, fmt.Errorf("store: наблюдения устройств: %w", err)
	}
	for rows.Next() {
		var id, source, t string
		if err := rows.Scan(&id, &source, &t); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: наблюдение устройства в списке: %w", err)
		}
		i, ok := idx[id]
		if !ok {
			continue
		}
		seenAt, err := time.Parse(time.RFC3339Nano, t)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: время наблюдения устройства %s: %w", id, err)
		}
		out[i].Observations = append(out[i].Observations, model.Observation{Source: source, Seen: seenAt})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: наблюдения устройств: %w", err)
	}
	return out, nil
}
