package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeFatSecret mimics the token and foods.search endpoints.
func fakeFatSecret(t *testing.T, ipBlocked *atomic.Bool, calls *atomic.Int32) *httptest.Server {
	m := http.NewServeMux()
	m.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "cid" || secret != "csecret" || r.FormValue("grant_type") != "client_credentials" {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"invalid_client"}`)
			return
		}
		fmt.Fprint(w, `{"access_token":"tok123","expires_in":86400,"token_type":"Bearer"}`)
	})
	m.HandleFunc("POST /api", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer tok123" {
			fmt.Fprint(w, `{"error":{"code":13,"message":"Invalid token"}}`)
			return
		}
		if ipBlocked.Load() {
			fmt.Fprint(w, `{"error":{"code":21,"message":"Invalid IP address detected: '203.0.113.9'"}}`)
			return
		}
		switch r.FormValue("search_expression") {
		case "one":
			fmt.Fprint(w, `{"foods":{"food":{"brand_name":"Taco Bell","food_description":"Per 1 taco - Calories: 170kcal | Fat: 9.00g | Carbs: 13.00g | Protein: 8.00g","food_id":"7","food_name":"Crunchy Taco","food_type":"Brand"},"max_results":"30","page_number":"0","total_results":"1"}}`)
		case "none":
			fmt.Fprint(w, `{"foods":{"max_results":"30","page_number":"0","total_results":"0"}}`)
		default:
			fmt.Fprint(w, `{"foods":{"food":[
			 {"brand_name":"McDonald's","food_description":"Per 1 burger - Calories: 590kcal | Fat: 34.00g | Carbs: 46.00g | Protein: 25.00g","food_id":"1","food_name":"Big Mac","food_type":"Brand"},
			 {"food_description":"Per 100g - Calories: 257kcal | Fat: 12.30g | Carbs: 20.10g | Protein: 14.70g","food_id":"2","food_name":"Hamburger","food_type":"Generic"},
			 {"food_description":"weird","food_id":"3","food_name":"Broken"}]}}`)
		}
	})
	s := httptest.NewServer(m)
	t.Cleanup(s.Close)
	return s
}

func TestFoodSearch(t *testing.T) {
	c := newTC(t)
	var blocked atomic.Bool
	var calls atomic.Int32
	fs := fakeFatSecret(t, &blocked, &calls)
	c.api.food.tokenURL, c.api.food.apiURL = fs.URL+"/token", fs.URL+"/api"
	tok, _, _ := c.register("ann", "Ann")

	// Off until keys are set.
	if st, _ := c.do("GET", "/api/v1/health", "", nil); st != 200 {
		t.Fatal(st)
	}
	_, h := c.do("GET", "/api/v1/health", "", nil)
	if h["foodSearch"] != false {
		t.Fatalf("health: %v", h)
	}
	if st, _ := c.do("GET", "/api/v1/foods/search?q=big+mac", tok, nil); st != 503 {
		t.Fatalf("want 503, got %d", st)
	}
	if st, _ := c.do("GET", "/api/v1/foods/search?q=big+mac", "", nil); st != 401 {
		t.Fatalf("want 401 without sign-in, got %d", st)
	}

	// Wrong secret.
	_ = c.api.store.Write(func(d *Data) error { d.FatSecretID, d.FatSecretSecret = "cid", "nope"; return nil })
	if st, _ := c.do("GET", "/api/v1/foods/search?q=big+mac", tok, nil); st != 502 {
		t.Fatalf("want 502 for bad keys, got %d", st)
	}
	if _, e, _ := c.api.food.Status(); !strings.Contains(e, "client ID or client secret") {
		t.Fatalf("lastErr = %q", e)
	}

	_ = c.api.store.Write(func(d *Data) error { d.FatSecretSecret = "csecret"; return nil })
	c.api.food.Forget()
	_, h = c.do("GET", "/api/v1/health", "", nil)
	if h["foodSearch"] != true {
		t.Fatalf("health: %v", h)
	}
	st, out := c.do("GET", "/api/v1/foods/search?q=big+mac", tok, nil)
	if st != 200 {
		t.Fatalf("search: %d %v", st, out)
	}
	foods := out["foods"].([]any)
	if len(foods) != 2 || out["attribution"] != "Powered by fatsecret" {
		t.Fatalf("foods: %v", out)
	}
	bm := foods[0].(map[string]any)
	if bm["name"] != "Big Mac" || bm["brand"] != "McDonald's" || bm["serving"] != "1 burger" || bm["kcal"] != 590.0 || bm["protein"] != 25.0 || bm["grams"] != 0.0 {
		t.Fatalf("big mac: %v", bm)
	}
	hb := foods[1].(map[string]any)
	if hb["serving"] != "100g" || hb["grams"] != 100.0 || hb["fat"] != 12.3 {
		t.Fatalf("hamburger: %v", hb)
	}

	// Cached: same query (any case/spacing) doesn't call FatSecret again.
	n := calls.Load()
	c.do("GET", "/api/v1/foods/search?q=BIG%20%20MAC", tok, nil)
	if calls.Load() != n {
		t.Fatal("expected a cache hit")
	}

	// Single result comes as an object; no results has no "food" key.
	_, out = c.do("GET", "/api/v1/foods/search?q=one", tok, nil)
	if f := out["foods"].([]any); len(f) != 1 || f[0].(map[string]any)["kcal"] != 170.0 {
		t.Fatalf("one: %v", out)
	}
	_, out = c.do("GET", "/api/v1/foods/search?q=none", tok, nil)
	if f := out["foods"].([]any); len(f) != 0 {
		t.Fatalf("none: %v", out)
	}

	// IP not allowed: user gets a plain error, the admin sees the IP.
	blocked.Store(true)
	if st, _ := c.do("GET", "/api/v1/foods/search?q=whopper", tok, nil); st != 502 {
		t.Fatalf("want 502, got %d", st)
	}
	if _, e, _ := c.api.food.Status(); !strings.Contains(e, "203.0.113.9") || !strings.Contains(e, "IP Restrictions") {
		t.Fatalf("lastErr = %q", e)
	}

	// Env vars win over panel keys.
	t.Setenv("FATSECRET_CLIENT_ID", "envid")
	t.Setenv("FATSECRET_CLIENT_SECRET", "envsecret")
	if id, _, env := c.api.food.creds(); id != "envid" || !env {
		t.Fatal("env creds not used")
	}

	if st, _ := c.do("GET", "/api/v1/foods/search?q="+strings.Repeat("a", 101), tok, nil); st != 400 {
		t.Fatalf("long query: %d", st)
	}
}
