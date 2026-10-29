// Маршруты точек изгиба карты NR-038 п.1: PUT /api/map/waypoints
// заменяет точки одной связи, GET отдаёт все, DELETE очищает;
// мусорное тело — 400, кривой ключ связи — 400, больше лимита — 413.
package api

import (
	"net/http"

	"github.com/ShkodnikAI/NetAtlas/server/store"
	"strings"
	"testing"
)

func TestMapWaypoints(t *testing.T) {
	h := testAPI(t, newFakeStore(), &fakeProber{})

	// PUT: три точки одной связи.
	rec := do(h, http.MethodPut, "/api/map/waypoints",
		`{"link":"00:00:5e:00:00:01|eth0|00:00:5e:00:00:02|","points":[{"x":20,"y":40},{"x":60,"y":40},{"x":60,"y":80}]}`,
		bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT точек: код %d, хочу 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"saved":3`) {
		t.Fatalf("PUT точек: хочу saved:3, ответ %s", rec.Body.String())
	}

	// GET отдаёт точки с индексами по порядку.
	rec2 := do(h, http.MethodGet, "/api/map/waypoints", "", bearer)
	if rec2.Code != http.StatusOK {
		t.Fatalf("GET /api/map/waypoints: код %d", rec2.Code)
	}
	body := rec2.Body.String()
	for _, want := range []string{`"link":"00:00:5e:00:00:01|eth0|00:00:5e:00:00:02|"`, `"idx":0`, `"idx":2`, `"x":60`, `"y":80`} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET точек: в ответе нет %s: %s", want, body)
		}
	}

	// Замена: две точки вместо трёх — старые стёрты.
	rec3 := do(h, http.MethodPut, "/api/map/waypoints",
		`{"link":"00:00:5e:00:00:01|eth0|00:00:5e:00:00:02|","points":[{"x":20,"y":20}]}`, bearer)
	if rec3.Code != http.StatusOK {
		t.Fatalf("замена: код %d", rec3.Code)
	}
	rec4 := do(h, http.MethodGet, "/api/map/waypoints", "", bearer)
	if strings.Contains(rec4.Body.String(), `"idx":1`) || strings.Contains(rec4.Body.String(), `"y":80`) {
		t.Fatalf("замена не стёрла старые точки: %s", rec4.Body.String())
	}

	// Пустой список — сброс изгибов связи.
	rec5 := do(h, http.MethodPut, "/api/map/waypoints",
		`{"link":"00:00:5e:00:00:01|eth0|00:00:5e:00:00:02|","points":[]}`, bearer)
	if rec5.Code != http.StatusOK {
		t.Fatalf("сброс: код %d", rec5.Code)
	}
	rec6 := do(h, http.MethodGet, "/api/map/waypoints", "", bearer)
	if strings.Contains(rec6.Body.String(), `"link"`) {
		t.Fatalf("после сброса точки остались: %s", rec6.Body.String())
	}
}

func TestMapWaypointsRejectsGarbage(t *testing.T) {
	h := testAPI(t, newFakeStore(), &fakeProber{})

	// Мусорное тело — 400.
	rec := do(h, http.MethodPut, "/api/map/waypoints", `{не json`, bearer)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("мусорное тело: код %d, хочу 400", rec.Code)
	}

	// Пустой ключ связи — 400.
	rec2 := do(h, http.MethodPut, "/api/map/waypoints", `{"link":"","points":[]}`, bearer)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("пустой ключ: код %d, хочу 400", rec2.Code)
	}

	// Управляющие символы в ключе — 400.
	rec3 := do(h, http.MethodPut, "/api/map/waypoints", `{"link":"a\u0007b","points":[]}`, bearer)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("управляющие символы: код %d, хочу 400", rec3.Code)
	}

	// Точек больше лимита — 413.
	var b strings.Builder
	b.WriteString(`{"link":"a||b|","points":[`)
	for i := 0; i <= store.MaxWaypointsPerLink; i++ {
		b.WriteString(`{"x":1,"y":2},`)
	}
	body := strings.TrimSuffix(b.String(), ",") + `]}`
	rec4 := do(h, http.MethodPut, "/api/map/waypoints", body, bearer)
	if rec4.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("больше лимита: код %d, хочу 413", rec4.Code)
	}
}

// DELETE /api/map/waypoints — «Выстроить сеткой»: стираются точки
// всех связей.
func TestMapWaypointsClearAll(t *testing.T) {
	h := testAPI(t, newFakeStore(), &fakeProber{})
	for _, link := range []string{"a||b|", "assumed:c"} {
		rec := do(h, http.MethodPut, "/api/map/waypoints",
			`{"link":"`+link+`","points":[{"x":1,"y":2}]}`, bearer)
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT %s: код %d", link, rec.Code)
		}
	}
	rec := do(h, http.MethodDelete, "/api/map/waypoints", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE: код %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"cleared":2`) {
		t.Fatalf("DELETE: хочу cleared:2, ответ %s", rec.Body.String())
	}
	rec2 := do(h, http.MethodGet, "/api/map/waypoints", "", bearer)
	if strings.Contains(rec2.Body.String(), `"link"`) {
		t.Fatalf("после DELETE точки остались: %s", rec2.Body.String())
	}
}
