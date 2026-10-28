package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FatSecret food search (brands and restaurant chains), proxied through this server so
// the API secret never ships inside the app. FatSecret also only answers requests from
// IP addresses listed in your FatSecret account, which a server can satisfy and phones can't.

const (
	fsTokenURL   = "https://oauth.fatsecret.com/connect/token"
	fsAPIURL     = "https://platform.fatsecret.com/rest/server.api"
	fsCacheTTL   = 24 * time.Hour
	fsCacheMax   = 2000
	fsMaxResults = 30
)

type FoodHit struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Brand   string  `json:"brand"`
	Serving string  `json:"serving"` // e.g. "1 burger", "100g"
	Grams   float64 `json:"grams"`   // 0 when the serving isn't given in grams
	Kcal    float64 `json:"kcal"`
	Fat     float64 `json:"fat"`
	Carbs   float64 `json:"carbs"`
	Protein float64 `json:"protein"`
}

type fsCached struct {
	at   time.Time
	hits []FoodHit
}

type FatSecret struct {
	store    *Store
	client   *http.Client
	tokenURL string
	apiURL   string
	now      func() time.Time

	mu       sync.Mutex
	token    string
	tokenFor string // client id the token belongs to
	expires  time.Time
	cache    map[string]fsCached
	lastErr  string
	lastErrT time.Time
	lastOK   time.Time
}

func NewFatSecret(store *Store) *FatSecret {
	return &FatSecret{
		store: store, client: &http.Client{Timeout: 15 * time.Second},
		tokenURL: fsTokenURL, apiURL: fsAPIURL, now: time.Now,
		cache: map[string]fsCached{},
	}
}

// creds: FATSECRET_CLIENT_ID / FATSECRET_CLIENT_SECRET win over what the admin panel saved.
func (f *FatSecret) creds() (id, secret string, fromEnv bool) {
	id, secret = os.Getenv("FATSECRET_CLIENT_ID"), os.Getenv("FATSECRET_CLIENT_SECRET")
	if id != "" && secret != "" {
		return strings.TrimSpace(id), strings.TrimSpace(secret), true
	}
	f.store.Read(func(d *Data) { id, secret = d.FatSecretID, d.FatSecretSecret })
	return id, secret, false
}

func (f *FatSecret) Enabled() bool {
	id, secret, _ := f.creds()
	return id != "" && secret != ""
}

// Forget drops the cached token and results (after the credentials change).
func (f *FatSecret) Forget() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token, f.tokenFor, f.expires = "", "", time.Time{}
	f.cache = map[string]fsCached{}
	f.lastErr, f.lastErrT, f.lastOK = "", time.Time{}, time.Time{}
}

// Status for the admin panel.
func (f *FatSecret) Status() (lastOK time.Time, lastErr string, lastErrT time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastOK, f.lastErr, f.lastErrT
}

var errNoFoodSearch = errors.New("fast-food search isn't set up on this server")

func (f *FatSecret) Search(ctx context.Context, query string) ([]FoodHit, error) {
	query = strings.Join(strings.Fields(query), " ")
	if query == "" {
		return []FoodHit{}, nil
	}
	key := strings.ToLower(query)
	f.mu.Lock()
	if c, ok := f.cache[key]; ok && f.now().Sub(c.at) < fsCacheTTL {
		f.mu.Unlock()
		return c.hits, nil
	}
	f.mu.Unlock()

	hits, err := f.search(ctx, query)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		if !errors.Is(err, errNoFoodSearch) {
			f.lastErr, f.lastErrT = err.Error(), f.now()
		}
		return nil, err
	}
	f.lastOK = f.now()
	if len(f.cache) >= fsCacheMax {
		for k, c := range f.cache {
			if f.now().Sub(c.at) >= fsCacheTTL || len(f.cache) >= fsCacheMax {
				delete(f.cache, k)
			}
		}
	}
	f.cache[key] = fsCached{at: f.now(), hits: hits}
	return hits, nil
}

func (f *FatSecret) search(ctx context.Context, query string) ([]FoodHit, error) {
	token, err := f.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"method":            {"foods.search"},
		"search_expression": {query},
		"max_results":       {strconv.Itoa(fsMaxResults)},
		"format":            {"json"},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, f.apiURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	body, status, err := f.do(req)
	if err != nil {
		return nil, err
	}
	if fe := fsError(body); fe != "" {
		if strings.Contains(fe, "token") { // expired or revoked token: get a new one next time
			f.mu.Lock()
			f.token = ""
			f.mu.Unlock()
		}
		return nil, fmt.Errorf("FatSecret: %s", fe)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("FatSecret answered HTTP %d", status)
	}
	return parseFoodsSearch(body)
}

func (f *FatSecret) accessToken(ctx context.Context) (string, error) {
	id, secret, _ := f.creds()
	if id == "" || secret == "" {
		return "", errNoFoodSearch
	}
	f.mu.Lock()
	if f.token != "" && f.tokenFor == id && f.now().Before(f.expires) {
		t := f.token
		f.mu.Unlock()
		return t, nil
	}
	f.mu.Unlock()

	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"basic"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, f.tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, secret)
	body, status, err := f.do(req)
	if err != nil {
		return "", err
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &tr)
	if status != http.StatusOK || tr.AccessToken == "" {
		msg := tr.Error
		if tr.ErrorDesc != "" {
			msg += ": " + tr.ErrorDesc
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", status)
		}
		if tr.Error == "invalid_client" {
			msg = "the client ID or client secret is wrong (invalid_client)"
		}
		return "", fmt.Errorf("FatSecret sign-in failed: %s", msg)
	}
	if tr.ExpiresIn <= 0 {
		tr.ExpiresIn = 86400
	}
	f.mu.Lock()
	f.token, f.tokenFor = tr.AccessToken, id
	f.expires = f.now().Add(time.Duration(tr.ExpiresIn)*time.Second - 5*time.Minute)
	f.mu.Unlock()
	return tr.AccessToken, nil
}

func (f *FatSecret) do(req *http.Request) ([]byte, int, error) {
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't reach FatSecret: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't read FatSecret's answer: %v", err)
	}
	return b, resp.StatusCode, nil
}

// fsError returns FatSecret's error message, e.g. code 21 "Invalid IP address detected: '1.2.3.4'".
func fsError(body []byte) string {
	var e struct {
		Error *struct {
			Code    json.Number `json:"code"`
			Message string      `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil || e.Error == nil {
		return ""
	}
	msg := e.Error.Message
	if e.Error.Code == "21" {
		msg += " — add this IP address under IP Restrictions in your FatSecret account"
	}
	return msg
}

// One-or-many: FatSecret sends a single result as an object instead of a one-item array.
type oneOrMany []json.RawMessage

func (o *oneOrMany) UnmarshalJSON(b []byte) error {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) > 0 && b[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*o = arr
		return nil
	}
	if string(b) == "null" {
		return nil
	}
	*o = []json.RawMessage{b}
	return nil
}

var fsDescRe = regexp.MustCompile(`(?i)^\s*per\s+(.+?)\s+-\s+calories:\s*([\d.]+)\s*kcal\s*\|\s*fat:\s*([\d.]+)\s*g\s*\|\s*carbs:\s*([\d.]+)\s*g\s*\|\s*protein:\s*([\d.]+)\s*g`)
var fsGramsRe = regexp.MustCompile(`(?i)^([\d.]+)\s*g$`)

func parseFoodsSearch(body []byte) ([]FoodHit, error) {
	var r struct {
		Foods struct {
			Food oneOrMany `json:"food"`
		} `json:"foods"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("unexpected answer from FatSecret")
	}
	out := []FoodHit{}
	for _, raw := range r.Foods.Food {
		var it struct {
			ID    string `json:"food_id"`
			Name  string `json:"food_name"`
			Brand string `json:"brand_name"`
			Desc  string `json:"food_description"`
		}
		if json.Unmarshal(raw, &it) != nil || it.Name == "" {
			continue
		}
		m := fsDescRe.FindStringSubmatch(it.Desc)
		if m == nil {
			continue
		}
		num := func(s string) float64 { v, _ := strconv.ParseFloat(s, 64); return v }
		h := FoodHit{ID: it.ID, Name: it.Name, Brand: it.Brand, Serving: m[1],
			Kcal: num(m[2]), Fat: num(m[3]), Carbs: num(m[4]), Protein: num(m[5])}
		if g := fsGramsRe.FindStringSubmatch(m[1]); g != nil {
			h.Grams = num(g[1])
		}
		out = append(out, h)
	}
	return out, nil
}

// publicIP asks a public service which address this server's traffic comes from,
// so the admin panel can say exactly what to allow in FatSecret.
func publicIP(ctx context.Context) string {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	c := &http.Client{Timeout: 8 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		log.Printf("public IP lookup failed: %v", err)
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	ip := strings.TrimSpace(string(b))
	if resp.StatusCode != http.StatusOK || len(ip) > 45 {
		return ""
	}
	return ip
}
