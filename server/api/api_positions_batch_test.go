// Маршруты позиций карты NR-035 п.1: PUT /api/map/positions пишет
// пакет, GET /api/map/positions отдаёт, DELETE /api/map/positions
// очищает; мусорное тело — 400, пакет больше лимита — 413.
package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestMapPositionsBatch(t *testing.T) {
	fs := newFakeStore()
	fs.addDev("00:00:5e:00:00:01")
	fs.addDev("00:80:77:00:00:01")
	h := testAPI(t, fs, &fakeProber{})

	// Пакет: оба существующих + один несуществующий (пропускается).
	rec := do(h, http.MethodPut, "/api/map/positions",
		`{"positions":[{"id":"00:00:5e:00:00:01","x":100,"y":120},{"id":"00:80:77:00:00:01","x":200,"y":240},{"id":"manual:none","x":1,"y":2}]}`,
		bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT пакета: код %d, хочу 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"saved":2`) {
		t.Fatalf("PUT пакета: хочу saved:2, ответ %s", rec.Body.String())
	}

	// GET /api/map/positions отдаёт обе позиции.
	rec2 := do(h, http.MethodGet, "/api/map/positions", "", bearer)
	if rec2.Code != http.StatusOK {
		t.Fatalf("GET /api/map/positions: код %d", rec2.Code)
	}
	body := rec2.Body.String()
	for _, want := range []string{`"id":"00:00:5e:00:00:01"`, `"x":100`, `"y":240`} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET пакета: в ответе нет %s: %s", want, body)
		}
	}

	// Мусорное тело — 400.
	rec3 := do(h, http.MethodPut, "/api/map/positions", `{не json`, bearer)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("мусорное тело: код %d, хочу 400", rec3.Code)
	}

	// Пакет больше лимита — 413.
	big := strings.Repeat(`{"id":"00:00:5e:00:00:01","x":1,"y":2},`, MaxPositionsBatch+1)
	rec4 := do(h, http.MethodPut, "/api/map/positions", `{"positions":[`+strings.TrimSuffix(big, ",")+`]}`, bearer)
	if rec4.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("пакет больше лимита: код %d, хочу 413", rec4.Code)
	}

	// DELETE /api/map/positions очищает.
	rec5 := do(h, http.MethodDelete, "/api/map/positions", "", bearer)
	if rec5.Code != http.StatusOK {
		t.Fatalf("DELETE /api/map/positions: код %d", rec5.Code)
	}
	rec6 := do(h, http.MethodGet, "/api/map/positions", "", bearer)
	if !strings.Contains(rec6.Body.String(), `"positions":[]`) && !strings.Contains(rec6.Body.String(), `"positions": null`) {
		if strings.Contains(rec6.Body.String(), `"id"`) {
			t.Fatalf("после DELETE позиции остались: %s", rec6.Body.String())
		}
	}
}
