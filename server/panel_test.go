package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

type ptc struct {
	t      *testing.T
	api    *API
	panel  *Panel
	srv    *httptest.Server // panel
	apiSrv *httptest.Server
	c      *http.Client
}

func newPTC(t *testing.T) *ptc {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Write(func(d *Data) error { d.SignupCode = "INVITE2026"; d.AdminSetupCode = "SETUP123"; return nil })
	api := NewAPI(st, Config{AllowSignup: true})
	panel := NewPanel(st, api, path, false)
	srv := httptest.NewServer(panel.Routes())
	apiSrv := httptest.NewServer(api.Routes())
	t.Cleanup(srv.Close)
	t.Cleanup(apiSrv.Close)
	jar, _ := cookiejar.New(nil)
	return &ptc{t: t, api: api, panel: panel, srv: srv, apiSrv: apiSrv, c: &http.Client{Jar: jar}}
}

func (p *ptc) get(path string) (int, string) {
	p.t.Helper()
	resp, err := p.c.Get(p.srv.URL + path)
	if err != nil {
		p.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (p *ptc) post(path string, form url.Values) (int, string) {
	p.t.Helper()
	resp, err := p.c.PostForm(p.srv.URL+path, form)
	if err != nil {
		p.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (p *ptc) csrf() string {
	_, body := p.get("/")
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		p.t.Fatalf("no csrf token on page")
	}
	return m[1]
}

func (p *ptc) setup() {
	p.t.Helper()
	st, body := p.post("/setup", url.Values{"code": {"setup123"}, "password": {"admin password 1"}, "password2": {"admin password 1"}})
	if st != 200 || !strings.Contains(body, "Admin password created") {
		p.t.Fatalf("setup failed: %d", st)
	}
}

func TestPanelSetupFlow(t *testing.T) {
	p := newPTC(t)
	_, body := p.get("/")
	if !strings.Contains(body, "Set up the admin panel") {
		t.Fatal("fresh server should show setup")
	}
	st, body := p.post("/setup", url.Values{"code": {"WRONG"}, "password": {"admin password 1"}, "password2": {"admin password 1"}})
	if st != 401 || !strings.Contains(body, "setup code is wrong") {
		t.Fatalf("wrong setup code: %d", st)
	}
	st, body = p.post("/setup", url.Values{"code": {"SETUP123"}, "password": {"short"}, "password2": {"short"}})
	if st != 401 || !strings.Contains(body, "at least 10") {
		t.Fatalf("short password accepted: %d", st)
	}
	p.setup()
	_, body = p.get("/")
	if !strings.Contains(body, "INVITE2026") || !strings.Contains(body, "Overview") {
		t.Fatal("dashboard should show the invite code")
	}
	// Setup can't be repeated by someone else once a password exists.
	other, _ := cookiejar.New(nil)
	p2 := &ptc{t: t, srv: p.srv, c: &http.Client{Jar: other}}
	p2.post("/setup", url.Values{"code": {"SETUP123"}, "password": {"attacker password"}, "password2": {"attacker password"}})
	_, body = p2.get("/")
	if !strings.Contains(body, "Admin sign-in") {
		t.Fatal("second setup should not log anyone in")
	}
	p.api.store.Read(func(d *Data) {
		if !checkPassword(d.AdminPassHash, "admin password 1") || d.AdminSetupCode != "" {
			t.Fatal("setup code must be consumed and password kept")
		}
	})
}

func TestPanelLoginAndLockout(t *testing.T) {
	p := newPTC(t)
	p.setup()
	p.post("/logout", url.Values{"csrf": {p.csrf()}})
	_, body := p.get("/")
	if !strings.Contains(body, "Admin sign-in") {
		t.Fatal("should be signed out")
	}
	st, _ := p.post("/login", url.Values{"password": {"nope"}})
	if st != 401 {
		t.Fatalf("wrong password: %d", st)
	}
	for i := 0; i < 8; i++ {
		p.post("/login", url.Values{"password": {"nope"}})
	}
	st, body = p.post("/login", url.Values{"password": {"admin password 1"}})
	if st != 401 || !strings.Contains(body, "Too many") {
		t.Fatalf("should be locked out: %d", st)
	}
}

func TestPanelPagesNeedLogin(t *testing.T) {
	p := newPTC(t)
	p.setup()
	anon, _ := cookiejar.New(nil)
	a := &ptc{t: t, srv: p.srv, c: &http.Client{Jar: anon, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	for _, path := range []string{"/users", "/challenges", "/settings"} {
		_, body := a.get(path)
		if !strings.Contains(body, "Admin sign-in") || strings.Contains(body, "INVITE2026") {
			t.Fatalf("%s leaked without login", path)
		}
	}
	st, _ := a.get("/backup")
	if st != http.StatusSeeOther {
		t.Fatalf("backup without login: %d", st)
	}
	st, _ = a.post("/users/delete", url.Values{"id": {"x"}, "confirm": {"yes"}})
	if st != http.StatusSeeOther {
		t.Fatalf("action without login: %d", st)
	}
}

func TestPanelCSRFAndOrigin(t *testing.T) {
	p := newPTC(t)
	p.setup()
	st, _ := p.post("/signups", url.Values{"open": {"0"}})
	if st != 403 {
		t.Fatalf("missing csrf must be refused: %d", st)
	}
	req, _ := http.NewRequest("POST", p.srv.URL+"/signups", strings.NewReader("open=0&csrf="+p.csrf()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := p.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-origin post must be refused: %d", resp.StatusCode)
	}
	if !p.api.signupOpen() {
		t.Fatal("refused requests must not change anything")
	}
}

func TestPanelRefusesPublicAddresses(t *testing.T) {
	p := newPTC(t)
	h := p.panel.Routes()
	for _, addr := range []string{"8.8.8.8:5000", "[2001:4860::8888]:5000"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = addr
		h.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatalf("%s should be refused, got %d", addr, rec.Code)
		}
	}
	for _, addr := range []string{"192.168.1.20:5000", "10.0.0.5:1", "100.101.102.103:1", "127.0.0.1:1", "172.18.0.1:1"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = addr
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s should be allowed, got %d", addr, rec.Code)
		}
	}
	// X-Forwarded-For must not be able to fake a private address.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "8.8.8.8:5000"
	req.Header.Set("X-Forwarded-For", "192.168.1.2")
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatal("forwarded header must be ignored by the panel")
	}
}

func TestPanelActions(t *testing.T) {
	p := newPTC(t)
	p.setup()
	// Create two app accounts through the real API.
	tc := &tc{t: t, srv: p.apiSrv, api: p.api}
	_, amyID, _ := tc.register("amy", "Amy")
	tc.register("ben", "Ben")

	// Close sign-ups: the app API must refuse new accounts.
	p.post("/signups", url.Values{"csrf": {p.csrf()}, "open": {"0"}})
	st, _ := tc.do("POST", "/api/v1/register", "", map[string]string{"username": "cat", "password": "correct horse", "displayName": "Cat", "signupCode": "INVITE2026"})
	if st != 403 {
		t.Fatalf("sign-ups should be closed: %d", st)
	}
	_, h := tc.do("GET", "/api/v1/health", "", nil)
	if h["signup"] != false {
		t.Fatal("health should report sign-ups closed")
	}

	// Custom invite code.
	p.post("/signups", url.Values{"csrf": {p.csrf()}, "open": {"1"}})
	p.post("/invite/set", url.Values{"csrf": {p.csrf()}, "code": {"family2026"}})
	p.api.store.Read(func(d *Data) {
		if d.SignupCode != "FAMILY2026" {
			t.Fatalf("invite code: %s", d.SignupCode)
		}
	})
	_, body := p.post("/invite/set", url.Values{"csrf": {p.csrf()}, "code": {"<script>"}})
	if !strings.Contains(body, "6–32 letters") {
		t.Fatal("bad invite code must be rejected")
	}

	// Rename (HTML in names is escaped on output).
	p.post("/users/rename", url.Values{"csrf": {p.csrf()}, "id": {amyID}, "name": {"<b>Amy</b>"}})
	_, body = p.get("/users")
	if strings.Contains(body, "<b><b>Amy</b></b>") || !strings.Contains(body, "&lt;b&gt;Amy&lt;/b&gt;") {
		t.Fatal("display names must be HTML-escaped")
	}

	// Reset password: shown once, works in the app, old sessions gone.
	_, body = p.post("/users/reset", url.Values{"csrf": {p.csrf()}, "id": {amyID}})
	m := regexp.MustCompile(`New password for <b>@amy</b>: <span class="code"[^>]*>([A-Z0-9]+)</span>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("new password not shown")
	}
	st, _ = tc.do("POST", "/api/v1/login", "", map[string]string{"username": "amy", "password": m[1]})
	if st != 200 {
		t.Fatalf("login with reset password: %d", st)
	}

	// Delete needs the confirmation box.
	p.post("/users/delete", url.Values{"csrf": {p.csrf()}, "id": {amyID}})
	p.api.store.Read(func(d *Data) {
		if d.Users[amyID] == nil {
			t.Fatal("deleted without confirmation")
		}
	})
	p.post("/users/delete", url.Values{"csrf": {p.csrf()}, "id": {amyID}, "confirm": {"yes"}})
	p.api.store.Read(func(d *Data) {
		if d.Users[amyID] != nil {
			t.Fatal("not deleted")
		}
	})

	// Backup download.
	st, body = p.get("/backup")
	if st != 200 || !strings.Contains(body, `"ben"`) {
		t.Fatalf("backup: %d", st)
	}
}

func TestPanelPasswordChangeAndCLIReset(t *testing.T) {
	p := newPTC(t)
	p.setup()
	_, body := p.post("/settings/password", url.Values{"csrf": {p.csrf()}, "current": {"wrong"}, "password": {"another password"}, "password2": {"another password"}})
	if !strings.Contains(body, "current admin password is wrong") {
		t.Fatal("wrong current password accepted")
	}
	_, body = p.post("/settings/password", url.Values{"csrf": {p.csrf()}, "current": {"admin password 1"}, "password": {"another password"}, "password2": {"another password"}})
	if !strings.Contains(body, "Admin password changed") {
		t.Fatal("password change failed")
	}
	// Command-line reset clears the password: existing panel sessions stop working.
	_ = p.api.store.Write(func(d *Data) error { d.AdminPassHash = ""; d.AdminSetupCode = "NEWSETUP"; return nil })
	_, body = p.get("/users")
	if !strings.Contains(body, "Set up the admin panel") {
		t.Fatal("reset must sign the panel out")
	}
}

func TestPanelFoodSearch(t *testing.T) {
	p := newPTC(t)
	var blocked atomic.Bool
	var calls atomic.Int32
	fs := fakeFatSecret(t, &blocked, &calls)
	p.api.food.tokenURL, p.api.food.apiURL = fs.URL+"/token", fs.URL+"/api"
	p.setup()

	_, body := p.get("/settings")
	if !strings.Contains(body, "Fast-food search (FatSecret)") || !strings.Contains(body, `class="pill off">Off`) {
		t.Fatal("food card missing or not off")
	}
	// Missing secret is refused.
	_, body = p.post("/food/save", url.Values{"csrf": {p.csrf()}, "id": {"cid"}})
	if !strings.Contains(body, "Enter both the client ID") {
		t.Fatal("expected keys error")
	}
	// No CSRF token: refused.
	p.post("/food/save", url.Values{"id": {"cid"}, "secret": {"csecret"}})
	if p.api.food.Enabled() {
		t.Fatal("saved without CSRF")
	}
	_, body = p.post("/food/save", url.Values{"csrf": {p.csrf()}, "id": {"cid"}, "secret": {"csecret"}})
	if !strings.Contains(body, "FatSecret keys saved") || strings.Contains(body, "csecret") {
		t.Fatal("save failed, or the secret was echoed back")
	}
	// Changing only the ID keeps the saved secret.
	p.post("/food/save", url.Values{"csrf": {p.csrf()}, "id": {"cid"}, "secret": {""}})
	if !p.api.food.Enabled() {
		t.Fatal("secret lost")
	}
	_, body = p.post("/food/test", url.Values{"csrf": {p.csrf()}})
	if !strings.Contains(body, "It works") || !strings.Contains(body, "Big Mac") {
		t.Fatalf("test failed: %s", between(body, "FatSecret)", "</form>"))
	}
	blocked.Store(true)
	_, body = p.post("/food/test", url.Values{"csrf": {p.csrf()}})
	if !strings.Contains(body, "203.0.113.9") || !strings.Contains(body, "Problem") {
		t.Fatalf("expected IP error: %s", between(body, "FatSecret)", "</form>"))
	}
	_, body = p.post("/food/remove", url.Values{"csrf": {p.csrf()}})
	if !strings.Contains(body, "keys removed") || p.api.food.Enabled() {
		t.Fatal("remove failed")
	}
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return s
	}
	s = s[i:]
	if j := strings.Index(s, b); j >= 0 {
		return s[:j]
	}
	return s
}
