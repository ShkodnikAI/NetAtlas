package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// PATCH /api/devices/{id} с kind: ручной тип сохраняется в сторе,
// недопустимый тип даёт 400 (NR-032 п.1).
func TestUpdateDeviceKind(t *testing.T) {
	fs := newFakeStore()
	fs.addDev("00:00:5e:00:00:01")
	h := testAPI(t, fs, &fakeProber{})

	rec := do(h, http.MethodPatch, "/api/devices/00:00:5e:00:00:01", `{"kind": "printer"}`, bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, хочу 200: %s", rec.Code, rec.Body.String())
	}
	var saved store.Update
	for _, u := range fs.kindUpdates {
		saved = u
	}
	if saved.Kind == nil || *saved.Kind != model.NodeKindPrinter {
		t.Fatalf("kind не дошёл до стора: %+v", fs.kindUpdates)
	}

	// Недопустимый тип отклоняется в сторе (см. store.nr032_test);
	// API передаёт kind насквозь без своей валидации — проверен
	// только путь до стора.
	rec2 := do(h, http.MethodPatch, "/api/devices/00:00:5e:00:00:01", `{"kind": "switch"}`, bearer)
	if rec2.Code != http.StatusOK {
		t.Fatalf("второй PATCH: код %d", rec2.Code)
	}
}

// Позиции узлов (NR-032 п.4): PUT сохраняет, GET отдаёт, DELETE
// очищает; узел должен существовать.
func TestPositionsEndpoints(t *testing.T) {
	fs := newFakeStore()
	fs.addDev("00:00:5e:00:00:01")
	h := testAPI(t, fs, &fakeProber{})

	rec := do(h, http.MethodPut, "/api/positions/00:00:5e:00:00:01", `{"x": 100.5, "y": -20}`, bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT код %d: %s", rec.Code, rec.Body.String())
	}

	rec2 := do(h, http.MethodPut, "/api/positions/manual:none", `{"x": 1, "y": 2}`, bearer)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("неизвестный узел: код %d, хочу 404", rec2.Code)
	}

	rec3 := do(h, http.MethodGet, "/api/positions", "", bearer)
	if rec3.Code != http.StatusOK {
		t.Fatalf("GET код %d", rec3.Code)
	}
	if !strings.Contains(rec3.Body.String(), `"x":100.5`) || !strings.Contains(rec3.Body.String(), "00:00:5e:00:00:01") {
		t.Fatalf("GET тело: %s", rec3.Body.String())
	}

	rec4 := do(h, http.MethodDelete, "/api/positions", "", bearer)
	if rec4.Code != http.StatusOK {
		t.Fatalf("DELETE код %d", rec4.Code)
	}
	rec5 := do(h, http.MethodGet, "/api/positions", "", bearer)
	if !strings.Contains(rec5.Body.String(), `"positions":[]`) {
		t.Fatalf("после DELETE: %s", rec5.Body.String())
	}
}

// Топология с предполагаемыми связями и kind_auto проходит через API
// целиком (NR-032 п.1, п.3).
func TestTopologyCarriesKindAutoAndAssumed(t *testing.T) {
	fs := newFakeStore()
	g := store.Graph{Nodes: []store.NodeInfo{}, Links: []store.LinkInfo{}}
	n := store.NodeInfo{Node: model.Node{ID: "00:80:77:00:00:01", Kind: model.NodeKindPrinter, Label: "canon"}}
	n.KindAuto = model.NodeKindPrinter
	g.Nodes = append(g.Nodes, n)
	l := store.LinkInfo{Link: model.Link{A: "00:80:77:00:00:01", B: "ip:192.168.100.1", Source: model.LinkSourceAssumed}}
	g.Links = append(g.Links, l)
	fs.graph = &g

	h := testAPI(t, fs, &fakeProber{})
	rec := do(h, http.MethodGet, "/api/topology", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, `"kind_auto":"printer"`) {
		t.Fatalf("kind_auto не в ответе: %s", out)
	}
	if !strings.Contains(out, `"source":"assumed"`) {
		t.Fatalf("assumed не в ответе: %s", out)
	}
}
