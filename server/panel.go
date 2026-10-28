package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // lets TZ work inside the minimal container image
	"unicode/utf8"
)

// Web admin panel. It listens on its own port (default 8097) that is never routed through the
// public tunnel / reverse proxy, refuses non-private client addresses unless ADMIN_ALLOW_PUBLIC
// is set, needs a password (created once with a setup code from the logs), and protects every
// form with a CSRF token. No JavaScript, no external assets.

const (
	panelCookie     = "feynos_admin"
	panelSessionTTL = 12 * time.Hour
)

type panelSession struct {
	expires time.Time
	csrf    string
}

type Panel struct {
	store        *Store
	api          *API
	dataPath     string
	allowPublic  bool
	secureCookie bool
	now          func() time.Time

	mu       sync.Mutex
	sessions map[string]*panelSession // key: sha256(token)
	fails    *limiter                 // failed logins per IP
	failsAll *limiter                 // failed logins overall
	tmpl     *template.Template

	foodTest   string // result of the last "Test" press, shown once
	foodTestOK bool
}

func NewPanel(store *Store, api *API, dataPath string, allowPublic bool) *Panel {
	p := &Panel{
		store: store, api: api, dataPath: dataPath, allowPublic: allowPublic, now: time.Now,
		sessions: map[string]*panelSession{},
		fails:    newLimiter(8, 15*time.Minute),
		failsAll: newLimiter(30, 15*time.Minute),
	}
	p.tmpl = template.Must(template.New("panel").Funcs(template.FuncMap{
		"ago":   p.ago,
		"date":  func(t time.Time) string { return t.Local().Format("Jan 2, 2006") },
		"num":   func(n int) string { return groupInt(n) },
		"short": prettyRange,
	}).Parse(panelHTML))
	return p
}

// ---------------------------------------------------------------- access control

var cgnat = mustCIDR("100.64.0.0/10") // Tailscale and other overlay networks

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func isPrivateAddr(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip)
}

func (p *Panel) Routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", p.page("home"))
	m.HandleFunc("GET /users", p.page("users"))
	m.HandleFunc("GET /challenges", p.page("challenges"))
	m.HandleFunc("GET /settings", p.page("settings"))
	m.HandleFunc("POST /setup", p.setup)
	m.HandleFunc("POST /login", p.login)
	m.HandleFunc("POST /logout", p.authed(p.logout))
	m.HandleFunc("POST /signups", p.authed(p.setSignups))
	m.HandleFunc("POST /invite/new", p.authed(p.newInvite))
	m.HandleFunc("POST /invite/set", p.authed(p.setInvite))
	m.HandleFunc("POST /users/rename", p.authed(p.renameUser))
	m.HandleFunc("POST /users/reset", p.authed(p.resetUser))
	m.HandleFunc("POST /users/signout", p.authed(p.signOutUser))
	m.HandleFunc("POST /users/delete", p.authed(p.deleteUser))
	m.HandleFunc("POST /challenges/delete", p.authed(p.deleteChallenge))
	m.HandleFunc("POST /settings/password", p.authed(p.changePassword))
	m.HandleFunc("GET /backup", p.authed(p.backup))
	m.HandleFunc("POST /food/save", p.authed(p.saveFood))
	m.HandleFunc("POST /food/test", p.authed(p.testFood))
	m.HandleFunc("POST /food/remove", p.authed(p.removeFood))
	return p.guard(m)
}

// guard: private networks only, small bodies, strict browser security headers.
func (p *Panel) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if !p.allowPublic && !isPrivateAddr(r.RemoteAddr) {
			log.Printf("admin panel: refused connection from public address %s", r.RemoteAddr)
			http.Error(w, "The admin panel is only available from your home network.", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			// Cross-site form posts are refused even before the CSRF token is checked.
			if o := r.Header.Get("Origin"); o != "" && o != "null" {
				host := strings.TrimPrefix(strings.TrimPrefix(o, "http://"), "https://")
				if host != r.Host {
					http.Error(w, "Cross-site request refused", http.StatusForbidden)
					return
				}
			}
			r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Panel) session(r *http.Request) *panelSession {
	c, err := r.Cookie(panelCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	var configured bool
	p.store.Read(func(d *Data) { configured = d.AdminPassHash != "" })
	if !configured { // password was reset from the command line: everyone is signed out
		p.endAllSessions()
		return nil
	}
	key := tokenKey(c.Value)
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.sessions[key]
	if s == nil || p.now().After(s.expires) {
		delete(p.sessions, key)
		return nil
	}
	return s
}

func (p *Panel) authed(next func(http.ResponseWriter, *http.Request, *panelSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := p.session(r)
		if s == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost && !constantEqual(r.PostFormValue("csrf"), s.csrf) {
			http.Error(w, "Your session form expired. Go back and reload the page.", http.StatusForbidden)
			return
		}
		next(w, r, s)
	}
}

func (p *Panel) startSession(w http.ResponseWriter) {
	token := randomToken()
	p.mu.Lock()
	for k, s := range p.sessions {
		if p.now().After(s.expires) {
			delete(p.sessions, k)
		}
	}
	p.sessions[tokenKey(token)] = &panelSession{expires: p.now().Add(panelSessionTTL), csrf: randomToken()}
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: panelCookie, Value: token, Path: "/", HttpOnly: true, Secure: p.secureCookie,
		SameSite: http.SameSiteStrictMode, MaxAge: int(panelSessionTTL.Seconds()),
	})
}

func (p *Panel) endAllSessions() {
	p.mu.Lock()
	p.sessions = map[string]*panelSession{}
	p.mu.Unlock()
}

// ---------------------------------------------------------------- page data

type panelUser struct {
	ID, Username, DisplayName string
	Created                   time.Time
	Friends, Pending          int
	Today, Week               int
	LastSync                  time.Time
	Devices                   int
}

type panelChallenge struct {
	ID, Name, Start, End, State, Creator string
	Joined, Invited                      int
	Top                                  []standing
}

type pageData struct {
	Page       string
	NeedsSetup bool
	LoggedIn   bool
	CSRF       string
	Flash      string
	FlashBad   bool
	Secret     string // one-time display, e.g. a reset password
	SecretFor  string

	Version     string
	SignupOpen  bool
	InviteCode  string
	Users       []panelUser
	Challenges  []panelChallenge
	Friendships int
	ActiveToday int
	ActiveCh    int
	DataSize    string
	Today       string
	Zone        string
	PublicURL   string

	FoodID        string
	FoodHasSecret bool
	FoodFromEnv   bool
	FoodLastOK    time.Time
	FoodLastErr   string
	FoodErrAt     time.Time
	FoodTest      string
	FoodTestOK    bool
}

var flashes = map[string]string{
	"in":        "Signed in.",
	"setup":     "Admin password created. You're signed in.",
	"open":      "Sign-ups are open. New people can join with the invite code.",
	"closed":    "Sign-ups are closed. Existing accounts keep working.",
	"invite":    "New invite code created. The old one no longer works.",
	"inviteset": "Invite code updated.",
	"renamed":   "Display name changed.",
	"signedout": "That person was signed out on all their devices.",
	"deleted":   "Account and all of its data deleted.",
	"chdeleted": "Challenge deleted.",
	"pw":        "Admin password changed. Other admin sessions were signed out.",
	"foodsaved": "FatSecret keys saved. Press Test to check they work.",
	"foodgone":  "FatSecret keys removed. Fast-food search is off.",
	"foodtest":  "",
}

var flashErrors = map[string]string{
	"badcode":  "Invite codes must be 6–32 letters or numbers.",
	"badname":  "Display names must be 1–40 characters.",
	"nouser":   "That account no longer exists.",
	"confirm":  "Tick the confirmation box first.",
	"pwwrong":  "Your current admin password is wrong.",
	"pwshort":  "Use at least 10 characters for the admin password.",
	"pwmatch":  "The two new passwords don't match.",
	"foodkeys": "Enter both the client ID and the client secret.",
}

func (p *Panel) build(r *http.Request, page string, s *panelSession) pageData {
	pd := pageData{Page: page, Version: version, Today: p.now().Format(dateLayout), Zone: p.now().Format("MST")}
	if k := r.URL.Query().Get("m"); k != "" {
		if v, ok := flashes[k]; ok {
			pd.Flash = v
		} else if v, ok := flashErrors[k]; ok {
			pd.Flash, pd.FlashBad = v, true
		}
	}
	p.store.Read(func(d *Data) { pd.NeedsSetup = d.AdminPassHash == "" })
	if s == nil {
		return pd
	}
	pd.LoggedIn, pd.CSRF = true, s.csrf
	fid, fsecret, fenv := p.api.food.creds()
	pd.FoodID, pd.FoodHasSecret, pd.FoodFromEnv = fid, fsecret != "", fenv
	pd.FoodLastOK, pd.FoodLastErr, pd.FoodErrAt = p.api.food.Status()
	if r.URL.Query().Get("m") == "foodtest" {
		p.mu.Lock()
		pd.FoodTest, pd.FoodTestOK = p.foodTest, p.foodTestOK
		p.mu.Unlock()
	}
	pd.SignupOpen = p.api.signupOpen()
	today := pd.Today
	t, _ := parseDate(today)
	weekStart := t.AddDate(0, 0, -6).Format(dateLayout)
	if fi, err := os.Stat(p.dataPath); err == nil {
		pd.DataSize = humanBytes(fi.Size())
	}
	p.store.Read(func(d *Data) {
		pd.InviteCode = d.SignupCode
		friends := map[string]int{}
		pending := map[string]int{}
		for _, f := range d.Friendships {
			if f.Accepted {
				friends[f.A]++
				friends[f.B]++
				pd.Friendships++
			} else {
				pending[f.A]++
				pending[f.B]++
			}
		}
		devices := map[string]int{}
		for _, ss := range d.Sessions {
			if p.now().Before(ss.Expires) {
				devices[ss.UserID]++
			}
		}
		for _, u := range d.Users {
			pu := panelUser{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Created: u.Created,
				Friends: friends[u.ID], Pending: pending[u.ID], Today: u.Steps[today], Week: sumSteps(u, weekStart, today),
				LastSync: u.StepsUpdate, Devices: devices[u.ID]}
			if !u.StepsUpdate.IsZero() && p.now().Sub(u.StepsUpdate) < 24*time.Hour {
				pd.ActiveToday++
			}
			pd.Users = append(pd.Users, pu)
		}
		for _, c := range d.Challenges {
			v := p.api.viewChallenge(d, c, "", today)
			pc := panelChallenge{ID: c.ID, Name: c.Name, Start: c.Start, End: c.End, State: v.State, Creator: v.CreatorName,
				Joined: len(v.Leaderboard), Invited: len(v.Invited)}
			if len(v.Leaderboard) > 3 {
				pc.Top = v.Leaderboard[:3]
			} else {
				pc.Top = v.Leaderboard
			}
			if v.State == "active" {
				pd.ActiveCh++
			}
			pd.Challenges = append(pd.Challenges, pc)
		}
	})
	sort.Slice(pd.Users, func(i, j int) bool { return pd.Users[i].Created.After(pd.Users[j].Created) })
	rank := map[string]int{"active": 0, "upcoming": 1, "finished": 2}
	sort.Slice(pd.Challenges, func(i, j int) bool {
		a, b := pd.Challenges[i], pd.Challenges[j]
		if rank[a.State] != rank[b.State] {
			return rank[a.State] < rank[b.State]
		}
		return a.End > b.End
	})
	return pd
}

func (p *Panel) render(w http.ResponseWriter, pd pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := p.tmpl.Execute(w, pd); err != nil {
		log.Printf("admin panel template: %v", err)
	}
}

func (p *Panel) page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := p.session(r)
		pd := p.build(r, name, s)
		if s == nil {
			pd.Page = "login"
			if pd.NeedsSetup {
				pd.Page = "setup"
			}
		}
		p.render(w, pd)
	}
}

func back(w http.ResponseWriter, r *http.Request, path, msg string) {
	http.Redirect(w, r, path+"?m="+msg, http.StatusSeeOther)
}

// ---------------------------------------------------------------- sign-in

func (p *Panel) clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (p *Panel) tooMany(r *http.Request) bool {
	return p.fails.Blocked(p.clientKey(r)) || p.failsAll.Blocked("all")
}

func (p *Panel) failed(r *http.Request) {
	p.fails.Hit(p.clientKey(r))
	p.failsAll.Hit("all")
}

func (p *Panel) loginError(w http.ResponseWriter, r *http.Request, page, msg string) {
	pd := p.build(r, page, nil)
	pd.Page = page
	pd.Flash, pd.FlashBad = msg, true
	w.WriteHeader(http.StatusUnauthorized)
	p.render(w, pd)
}

func (p *Panel) setup(w http.ResponseWriter, r *http.Request) {
	if p.tooMany(r) {
		p.loginError(w, r, "setup", "Too many attempts. Wait 15 minutes and try again.")
		return
	}
	code := strings.ToUpper(strings.TrimSpace(r.PostFormValue("code")))
	pw, pw2 := r.PostFormValue("password"), r.PostFormValue("password2")
	var setupCode, existing string
	p.store.Read(func(d *Data) { setupCode, existing = d.AdminSetupCode, d.AdminPassHash })
	if existing != "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if setupCode == "" || !constantEqual(code, setupCode) {
		p.failed(r)
		p.loginError(w, r, "setup", "That setup code is wrong. Run the command shown below on your server to see it.")
		return
	}
	if utf8.RuneCountInString(pw) < 10 {
		p.loginError(w, r, "setup", flashErrors["pwshort"])
		return
	}
	if pw != pw2 {
		p.loginError(w, r, "setup", flashErrors["pwmatch"])
		return
	}
	hash, err := hashPassword(pw)
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	_ = p.store.Write(func(d *Data) error {
		d.AdminPassHash = hash
		d.AdminSetupCode = ""
		return nil
	})
	log.Printf("admin panel: admin password created from %s", p.clientKey(r))
	p.startSession(w)
	back(w, r, "/", "setup")
}

func (p *Panel) login(w http.ResponseWriter, r *http.Request) {
	if p.tooMany(r) {
		p.loginError(w, r, "login", "Too many wrong passwords. Wait 15 minutes and try again.")
		return
	}
	var hash string
	p.store.Read(func(d *Data) { hash = d.AdminPassHash })
	if hash == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !checkPassword(hash, r.PostFormValue("password")) {
		p.failed(r)
		log.Printf("admin panel: wrong password from %s", p.clientKey(r))
		p.loginError(w, r, "login", "Wrong password.")
		return
	}
	p.fails.Reset(p.clientKey(r))
	p.startSession(w)
	back(w, r, "/", "in")
}

func (p *Panel) logout(w http.ResponseWriter, r *http.Request, _ *panelSession) {
	if c, err := r.Cookie(panelCookie); err == nil {
		p.mu.Lock()
		delete(p.sessions, tokenKey(c.Value))
		p.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: panelCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---------------------------------------------------------------- actions

func (p *Panel) setSignups(w http.ResponseWriter, r *http.Request, _ *panelSession) {
	open := r.PostFormValue("open") == "1"
	_ = p.store.Write(func(d *Data) error { d.SignupOpen = &open; return nil })
	log.Printf("admin: sign-ups %s", map[bool]string{true: "opened", false: "closed"}[open])
	back(w, r, "/", map[bool]string{true: "open", false: "closed"}[open])
}

func (p *Panel) newInvite(w http.ResponseWriter, r *http.Request, _ *panelSession) {
	_ = p.store.Write(func(d *Data) error { d.SignupCode = randomCode(10); return nil })
	log.Printf("admin: invite code rotated")
	back(w, r, "/", "invite")
}

func (p *Panel) setInvite(w http.ResponseWriter, r *http.Request, _ *panelSession) {
	code := strings.ToUpper(strings.TrimSpace(r.PostFormValue("code")))
	ok := len(code) >= 6 && len(code) <= 32
	for _, c := range code {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			ok = false
		}
	}
	if !ok {
		back(w, r, "/", "badcode")
		return
	}
	_ = p.store.Write(func(d *Data) error { d.SignupCode = code; return nil })
	log.Printf("admin: invite code changed")
	back(w, r, "/", "inviteset")
}

func (p *Panel) renameUser(w http.ResponseWriter, r *http.Request, _ *panelSession) {
	name, err := cleanDisplayName(r.PostFormValue("name"))
	if err != nil {
		back(w, r, "/users", "badname")
		return
	}
	err = p.store.Write(func(d *Data) error {
		u := d.Users[r.PostFormValue("id")]
		if u == nil {
			return fail(404, "nouser")
		}
		u.DisplayName = name
		return nil
	})
	if err != nil {
		back(w, r, "/users", "nouser")
		return
	}
	back(w, r, "/users", "renamed")
}

func (p *Panel) resetUser(w http.ResponseWriter, r *http.Request, s *panelSession) {
	pw := randomCode(12)
	hash, err := hashPassword(pw)
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	var who string
	err = p.store.Write(func(d *Data) error {
		u := d.Users[r.PostFormValue("id")]
		if u == nil {
			return fail(404, "nouser")
		}
		u.PassHash = hash
		who = u.Username
		for k, ss := range d.Sessions {
			if ss.UserID == u.ID {
				delete(d.Sessions, k)
			}
		}
		return nil
	})
	if err != nil {
		back(w, r, "/users", "nouser")
		return
	}
	log.Printf("admin: password reset for %s", who)
	// Shown once, straight in the response — never put in a URL or log.
	pd := p.build(r, "users", s)
	pd.Secret, pd.SecretFor = pw, who
	p.render(w, pd)
}

func (p *Panel) signOutUser(w http.ResponseWriter, r *http.Request, _ *panelSession) {
	id := r.PostFormValue("id")
	_ = p.store.Write(func(d *Data) error {
		for k, ss := range d.Sessions {
			if ss.UserID == id {
				delete(d.Sessions, k)
			}
		}
		return nil
	})
	back(w, r, "/users", "signedout")
}

func (p *Panel) deleteUser(w http.ResponseWriter, r *http.Request, _ *panelSession) {
	if r.PostFormValue("confirm") != "yes" {
		back(w, r, "/users", "confirm")
		return
	}
	var who string
	err := p.store.Write(func(d *Data) error {
		u := d.Users[r.PostFormValue("id")]
		if u == nil {
			return fail(404, "nouser")
		}
		who = u.Username
		d.deleteUser(u.ID)
		return nil
	})
	if err != nil {
		back(w, r, "/users", "nouser")
		return
	}
	log.Printf("admin: deleted account %s", who)
	back(w, r, "/users", "deleted")
}

func (p *Panel) deleteChallenge(w http.ResponseWriter, r *http.Request, _ *panelSession) {
	if r.PostFormValue("confirm") != "yes" {
		back(w, r, "/challenges", "confirm")
		return
	}
	_ = p.store.Write(func(d *Data) error { delete(d.Challenges, r.PostFormValue("id")); return nil })
	back(w, r, "/challenges", "chdeleted")
}

func (p *Panel) changePassword(w http.ResponseWriter, r *http.Request, _ *panelSession) {
	var hash string
	p.store.Read(func(d *Data) { hash = d.AdminPassHash })
	if p.tooMany(r) || !checkPassword(hash, r.PostFormValue("current")) {
		p.failed(r)
		back(w, r, "/settings", "pwwrong")
		return
	}
	pw := r.PostFormValue("password")
	if utf8.RuneCountInString(pw) < 10 {
		back(w, r, "/settings", "pwshort")
		return
	}
	if pw != r.PostFormValue("password2") {
		back(w, r, "/settings", "pwmatch")
		return
	}
	newHash, err := hashPassword(pw)
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	_ = p.store.Write(func(d *Data) error { d.AdminPassHash = newHash; return nil })
	p.endAllSessions()
	p.startSession(w)
	log.Printf("admin: admin password changed")
	back(w, r, "/settings", "pw")
}

// backup downloads the whole data file (includes password hashes — keep it private).
func (p *Panel) backup(w http.ResponseWriter, r *http.Request, _ *panelSession) {
	var b []byte
	p.store.Read(func(d *Data) { b, _ = json.MarshalIndent(d, "", "  ") })
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="feynos-fit-server-%s.json"`, p.now().Format("2006-01-02")))
	_, _ = w.Write(b)
	log.Printf("admin: backup downloaded")
}

func (p *Panel) saveFood(w http.ResponseWriter, r *http.Request, _ *panelSession) {
	id := strings.TrimSpace(r.PostFormValue("id"))
	secret := strings.TrimSpace(r.PostFormValue("secret"))
	var had string
	p.store.Read(func(d *Data) { had = d.FatSecretSecret })
	if secret == "" {
		secret = had // keep the saved secret when only the ID changes
	}
	if id == "" || secret == "" || len(id) > 200 || len(secret) > 200 {
		back(w, r, "/settings", "foodkeys")
		return
	}
	_ = p.store.Write(func(d *Data) error { d.FatSecretID, d.FatSecretSecret = id, secret; return nil })
	p.api.food.Forget()
	log.Printf("admin: FatSecret keys saved")
	back(w, r, "/settings", "foodsaved")
}

func (p *Panel) removeFood(w http.ResponseWriter, r *http.Request, _ *panelSession) {
	_ = p.store.Write(func(d *Data) error { d.FatSecretID, d.FatSecretSecret = "", ""; return nil })
	p.api.food.Forget()
	log.Printf("admin: FatSecret keys removed")
	back(w, r, "/settings", "foodgone")
}

func (p *Panel) testFood(w http.ResponseWriter, r *http.Request, _ *panelSession) {
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	f := p.api.food
	var msg string
	ok := false
	if !f.Enabled() {
		msg = "Enter your FatSecret client ID and secret first."
	} else if hits, err := f.search(ctx, "big mac"); err != nil {
		f.mu.Lock()
		f.lastErr, f.lastErrT = err.Error(), f.now()
		f.mu.Unlock()
		msg = err.Error()
		if ip := publicIP(ctx); ip != "" {
			msg += fmt.Sprintf(". This server's public IP address is %s — make sure it's listed under IP Restrictions in your FatSecret account (changes can take up to 24 hours to apply).", ip)
		}
	} else {
		f.mu.Lock()
		f.lastOK = f.now()
		f.mu.Unlock()
		ok = true
		msg = fmt.Sprintf("It works: a search for \"big mac\" found %d foods.", len(hits))
		if len(hits) > 0 {
			h := hits[0]
			msg += fmt.Sprintf(" First result: %s%s, per %s: %.0f kcal.", h.Name, map[bool]string{true: " (" + h.Brand + ")", false: ""}[h.Brand != ""], h.Serving, h.Kcal)
		}
	}
	p.mu.Lock()
	p.foodTest, p.foodTestOK = msg, ok
	p.mu.Unlock()
	back(w, r, "/settings", "foodtest")
}

// ---------------------------------------------------------------- formatting

func (p *Panel) ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := p.now().Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

func groupInt(n int) string {
	s := fmt.Sprint(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func prettyRange(start, end string) string {
	s, ok1 := parseDate(start)
	e, ok2 := parseDate(end)
	if !ok1 || !ok2 {
		return start + " – " + end
	}
	if s.Equal(e) {
		return s.Format("Jan 2")
	}
	return s.Format("Jan 2") + " – " + e.Format("Jan 2")
}

func humanBytes(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/1024/1024)
	}
}
