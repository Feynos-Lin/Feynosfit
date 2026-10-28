package main

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	dateLayout       = "2006-01-02"
	sessionTTL       = 180 * 24 * time.Hour
	maxSessions      = 10
	maxBody          = 64 << 10
	maxChallengeDays = 92
	maxMembers       = 25
	maxStepsPerDay   = 150_000
)

type Config struct {
	AllowSignup bool
	TrustProxy  bool
}

type API struct {
	store    *Store
	cfg      Config
	authIP   *limiter // login/register attempts per client IP
	failUser *limiter // failed logins per username
	friendIP *limiter // friend-code lookups per user (stops code guessing)
	now      func() time.Time
}

func NewAPI(store *Store, cfg Config) *API {
	return &API{
		store:    store,
		cfg:      cfg,
		authIP:   newLimiter(30, 10*time.Minute),
		failUser: newLimiter(10, 15*time.Minute),
		friendIP: newLimiter(20, 10*time.Minute),
		now:      time.Now,
	}
}

func (a *API) Routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/v1/health", a.health)
	m.HandleFunc("POST /api/v1/register", a.register)
	m.HandleFunc("POST /api/v1/login", a.login)
	m.HandleFunc("POST /api/v1/logout", a.auth(a.logout))
	m.HandleFunc("GET /api/v1/me", a.auth(a.me))
	m.HandleFunc("PATCH /api/v1/me", a.auth(a.updateMe))
	m.HandleFunc("POST /api/v1/me", a.auth(a.updateMe)) // Android's HttpURLConnection has no PATCH
	m.HandleFunc("POST /api/v1/me/password", a.auth(a.changePassword))
	m.HandleFunc("POST /api/v1/me/delete", a.auth(a.deleteMe))
	m.HandleFunc("PUT /api/v1/steps", a.auth(a.putSteps))
	m.HandleFunc("GET /api/v1/friends", a.auth(a.listFriends))
	m.HandleFunc("POST /api/v1/friends", a.auth(a.addFriend))
	m.HandleFunc("POST /api/v1/friends/{id}/accept", a.auth(a.acceptFriend))
	m.HandleFunc("DELETE /api/v1/friends/{id}", a.auth(a.removeFriend))
	m.HandleFunc("GET /api/v1/challenges", a.auth(a.listChallenges))
	m.HandleFunc("POST /api/v1/challenges", a.auth(a.createChallenge))
	m.HandleFunc("POST /api/v1/challenges/{id}/join", a.auth(a.joinChallenge))
	m.HandleFunc("POST /api/v1/challenges/{id}/leave", a.auth(a.leaveChallenge))
	m.HandleFunc("DELETE /api/v1/challenges/{id}", a.auth(a.deleteChallenge))
	return secureHeaders(m)
}

// ---------------------------------------------------------------- plumbing

type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func fail(status int, msg string) error { return &apiError{status, msg} }

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'")
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeJSON(w, ae.status, map[string]string{"error": ae.msg})
		return
	}
	log.Printf("internal error: %v", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error"})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return fail(http.StatusBadRequest, "Invalid request")
	}
	return nil
}

func (a *API) clientIP(r *http.Request) string {
	if a.cfg.TrustProxy {
		if v := r.Header.Get("CF-Connecting-IP"); v != "" {
			return strings.TrimSpace(v)
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
		if v := r.Header.Get("X-Real-IP"); v != "" {
			return strings.TrimSpace(v)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type authed func(w http.ResponseWriter, r *http.Request, u *User, tokenKey string)

func (a *API) auth(next authed) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(h, "Bearer ")
		if !ok || token == "" {
			writeErr(w, fail(http.StatusUnauthorized, "Please sign in"))
			return
		}
		key := tokenKey(token)
		var user *User
		a.store.Read(func(d *Data) {
			if s := d.Sessions[key]; s != nil && a.now().Before(s.Expires) {
				user = d.Users[s.UserID]
			}
		})
		if user == nil {
			writeErr(w, fail(http.StatusUnauthorized, "Your session has expired. Please sign in again."))
			return
		}
		next(w, r, user, key)
	}
}

// signupOpen: the admin panel's switch if it has been used, otherwise ALLOW_SIGNUP.
func (a *API) signupOpen() bool {
	open := a.cfg.AllowSignup
	a.store.Read(func(d *Data) {
		if d.SignupOpen != nil {
			open = *d.SignupOpen
		}
	})
	return open
}

// ---------------------------------------------------------------- validation

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{2,31}$`)

func cleanUsername(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !usernameRe.MatchString(s) {
		return "", fail(http.StatusBadRequest, "Usernames are 3–32 characters: letters, numbers, dot, dash or underscore")
	}
	return s, nil
}

func cleanDisplayName(s string) (string, error) {
	s = strings.TrimSpace(s)
	n := utf8.RuneCountInString(s)
	if n < 1 || n > 40 {
		return "", fail(http.StatusBadRequest, "Display name must be 1–40 characters")
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", fail(http.StatusBadRequest, "Display name contains invalid characters")
		}
	}
	return s, nil
}

func checkNewPassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < 8 || n > 128 {
		return fail(http.StatusBadRequest, "Passwords must be 8–128 characters")
	}
	return nil
}

func parseDate(s string) (time.Time, bool) {
	t, err := time.Parse(dateLayout, s)
	return t, err == nil && t.Format(dateLayout) == s
}

// clientToday is the caller's local date, sanity-checked against the server clock (±2 days).
func (a *API) clientToday(r *http.Request) string {
	server := a.now().UTC()
	if v := r.URL.Query().Get("today"); v != "" {
		if t, ok := parseDate(v); ok {
			diff := t.Sub(server.Truncate(24 * time.Hour))
			if diff > -50*time.Hour && diff < 50*time.Hour {
				return v
			}
		}
	}
	return server.Format(dateLayout)
}

// ---------------------------------------------------------------- views

type userView struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	FriendCode  string `json:"friendCode,omitempty"`
}

func meView(u *User) userView {
	return userView{u.ID, u.Username, u.DisplayName, u.FriendCode}
}

func publicView(u *User) userView {
	return userView{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName}
}

func sumSteps(u *User, start, end string) int {
	total := 0
	for day, n := range u.Steps {
		if day >= start && day <= end {
			total += n
		}
	}
	return total
}

// ---------------------------------------------------------------- handlers: account

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "feynos-fit", "version": version, "signup": a.signupOpen()})
}

type authResponse struct {
	Token string   `json:"token"`
	User  userView `json:"user"`
}

func (a *API) newSession(d *Data, userID string) string {
	token := randomToken()
	now := a.now()
	d.Sessions[tokenKey(token)] = &Session{UserID: userID, Created: now, Expires: now.Add(sessionTTL)}
	keys := d.sessionsOf(userID)
	for len(keys) > maxSessions {
		delete(d.Sessions, keys[0])
		keys = keys[1:]
	}
	return token
}

func (a *API) register(w http.ResponseWriter, r *http.Request) {
	if !a.authIP.Allow(a.clientIP(r)) {
		writeErr(w, fail(http.StatusTooManyRequests, "Too many attempts. Try again in a few minutes."))
		return
	}
	if !a.signupOpen() {
		writeErr(w, fail(http.StatusForbidden, "New sign-ups are turned off on this server"))
		return
	}
	var req struct {
		Username, Password, DisplayName, SignupCode string
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	var code string
	a.store.Read(func(d *Data) { code = d.SignupCode })
	if code == "" || !constantEqual(strings.ToUpper(strings.TrimSpace(req.SignupCode)), code) {
		writeErr(w, fail(http.StatusForbidden, "That server invite code is wrong. Ask the server owner for it."))
		return
	}
	name, err := cleanUsername(req.Username)
	if err != nil {
		writeErr(w, err)
		return
	}
	display, err := cleanDisplayName(req.DisplayName)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := checkNewPassword(req.Password); err != nil {
		writeErr(w, err)
		return
	}
	hash, err := hashPassword(req.Password)
	if err != nil {
		writeErr(w, err)
		return
	}
	var resp authResponse
	err = a.store.Write(func(d *Data) error {
		if d.userByName(name) != nil {
			return fail(http.StatusConflict, "That username is taken")
		}
		code := randomCode(8)
		for d.userByFriendCode(code) != nil {
			code = randomCode(8)
		}
		u := &User{ID: randomID(), Username: name, DisplayName: display, PassHash: hash, FriendCode: code,
			Created: a.now(), Steps: map[string]int{}}
		d.Users[u.ID] = u
		resp = authResponse{Token: a.newSession(d, u.ID), User: meView(u)}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	log.Printf("new account: %s", name)
	writeJSON(w, http.StatusCreated, resp)
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if !a.authIP.Allow(a.clientIP(r)) {
		writeErr(w, fail(http.StatusTooManyRequests, "Too many attempts. Try again in a few minutes."))
		return
	}
	var req struct{ Username, Password string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Username))
	if a.failUser.Blocked(name) {
		writeErr(w, fail(http.StatusTooManyRequests, "Too many failed sign-ins for this account. Try again in 15 minutes."))
		return
	}
	var u *User
	var hash string
	a.store.Read(func(d *Data) {
		if u = d.userByName(name); u != nil {
			hash = u.PassHash
		}
	})
	if u == nil {
		checkPassword(dummyHash, req.Password)
		a.failUser.Hit(name)
		writeErr(w, fail(http.StatusUnauthorized, "Wrong username or password"))
		return
	}
	if !checkPassword(hash, req.Password) {
		a.failUser.Hit(name)
		writeErr(w, fail(http.StatusUnauthorized, "Wrong username or password"))
		return
	}
	a.failUser.Reset(name)
	var resp authResponse
	err := a.store.Write(func(d *Data) error {
		cur := d.Users[u.ID]
		if cur == nil {
			return fail(http.StatusUnauthorized, "Wrong username or password")
		}
		resp = authResponse{Token: a.newSession(d, cur.ID), User: meView(cur)}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) logout(w http.ResponseWriter, r *http.Request, u *User, key string) {
	_ = a.store.Write(func(d *Data) error {
		delete(d.Sessions, key)
		return nil
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *API) me(w http.ResponseWriter, r *http.Request, u *User, _ string) {
	var v userView
	a.store.Read(func(d *Data) { v = meView(d.Users[u.ID]) })
	writeJSON(w, http.StatusOK, v)
}

func (a *API) updateMe(w http.ResponseWriter, r *http.Request, u *User, _ string) {
	var req struct {
		DisplayName *string `json:"displayName"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	var v userView
	err := a.store.Write(func(d *Data) error {
		cur := d.Users[u.ID]
		if req.DisplayName != nil {
			name, err := cleanDisplayName(*req.DisplayName)
			if err != nil {
				return err
			}
			cur.DisplayName = name
		}
		v = meView(cur)
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request, u *User, key string) {
	var req struct{ Current, New string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if a.failUser.Blocked(u.Username) {
		writeErr(w, fail(http.StatusTooManyRequests, "Too many wrong passwords. Try again in 15 minutes."))
		return
	}
	if !checkPassword(u.PassHash, req.Current) {
		a.failUser.Hit(u.Username)
		writeErr(w, fail(http.StatusForbidden, "Your current password is wrong"))
		return
	}
	if err := checkNewPassword(req.New); err != nil {
		writeErr(w, err)
		return
	}
	hash, err := hashPassword(req.New)
	if err != nil {
		writeErr(w, err)
		return
	}
	err = a.store.Write(func(d *Data) error {
		d.Users[u.ID].PassHash = hash
		for k, s := range d.Sessions { // sign out every other device
			if s.UserID == u.ID && k != key {
				delete(d.Sessions, k)
			}
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *API) deleteMe(w http.ResponseWriter, r *http.Request, u *User, _ string) {
	var req struct{ Password string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if a.failUser.Blocked(u.Username) {
		writeErr(w, fail(http.StatusTooManyRequests, "Too many wrong passwords. Try again in 15 minutes."))
		return
	}
	if !checkPassword(u.PassHash, req.Password) {
		a.failUser.Hit(u.Username)
		writeErr(w, fail(http.StatusForbidden, "Wrong password"))
		return
	}
	if err := a.store.Write(func(d *Data) error { d.deleteUser(u.ID); return nil }); err != nil {
		writeErr(w, err)
		return
	}
	log.Printf("account deleted: %s", u.Username)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- handlers: steps

func (a *API) putSteps(w http.ResponseWriter, r *http.Request, u *User, _ string) {
	var req struct {
		Days []struct {
			Date  string `json:"date"`
			Steps int    `json:"steps"`
		} `json:"days"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if len(req.Days) == 0 || len(req.Days) > 62 {
		writeErr(w, fail(http.StatusBadRequest, "Send between 1 and 62 days"))
		return
	}
	now := a.now().UTC()
	earliest := now.AddDate(0, 0, -60).Format(dateLayout)
	latest := now.AddDate(0, 0, 1).Format(dateLayout) // time zones ahead of UTC
	for _, day := range req.Days {
		if _, ok := parseDate(day.Date); !ok || day.Date < earliest || day.Date > latest {
			writeErr(w, fail(http.StatusBadRequest, "Step dates must be within the last 60 days"))
			return
		}
		if day.Steps < 0 || day.Steps > maxStepsPerDay {
			writeErr(w, fail(http.StatusBadRequest, "Step counts must be between 0 and 150,000"))
			return
		}
	}
	err := a.store.Write(func(d *Data) error {
		cur := d.Users[u.ID]
		for _, day := range req.Days {
			if day.Steps == 0 {
				delete(cur.Steps, day.Date)
			} else {
				cur.Steps[day.Date] = day.Steps
			}
		}
		cur.StepsUpdate = a.now()
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- handlers: friends

type friendView struct {
	userView
	Today       int        `json:"today"`
	Week        int        `json:"week"`
	LastUpdated *time.Time `json:"lastUpdated,omitempty"`
}

func (a *API) listFriends(w http.ResponseWriter, r *http.Request, u *User, _ string) {
	today := a.clientToday(r)
	t, _ := parseDate(today)
	weekStart := t.AddDate(0, 0, -6).Format(dateLayout)
	resp := struct {
		Friends  []friendView `json:"friends"`
		Incoming []userView   `json:"incoming"`
		Outgoing []userView   `json:"outgoing"`
		Me       friendView   `json:"me"`
	}{Friends: []friendView{}, Incoming: []userView{}, Outgoing: []userView{}}
	a.store.Read(func(d *Data) {
		me := d.Users[u.ID]
		resp.Me = friendView{userView: meView(me), Today: me.Steps[today], Week: sumSteps(me, weekStart, today)}
		for _, f := range d.Friendships {
			var other string
			switch u.ID {
			case f.A:
				other = f.B
			case f.B:
				other = f.A
			default:
				continue
			}
			o := d.Users[other]
			if o == nil {
				continue
			}
			switch {
			case f.Accepted:
				fv := friendView{userView: publicView(o), Today: o.Steps[today], Week: sumSteps(o, weekStart, today)}
				if !o.StepsUpdate.IsZero() {
					t := o.StepsUpdate
					fv.LastUpdated = &t
				}
				resp.Friends = append(resp.Friends, fv)
			case f.Requester == u.ID:
				resp.Outgoing = append(resp.Outgoing, publicView(o))
			default:
				resp.Incoming = append(resp.Incoming, publicView(o))
			}
		}
	})
	sort.Slice(resp.Friends, func(i, j int) bool { return resp.Friends[i].Today > resp.Friends[j].Today })
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) addFriend(w http.ResponseWriter, r *http.Request, u *User, _ string) {
	if !a.friendIP.Allow("u:" + u.ID) {
		writeErr(w, fail(http.StatusTooManyRequests, "Too many friend requests. Try again in a few minutes."))
		return
	}
	var req struct{ Code string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	code := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(req.Code), " ", ""))
	code = strings.ReplaceAll(code, "-", "")
	var result string
	err := a.store.Write(func(d *Data) error {
		o := d.userByFriendCode(code)
		if o == nil || code == "" {
			return fail(http.StatusNotFound, "No one on this server has that friend code")
		}
		if o.ID == u.ID {
			return fail(http.StatusBadRequest, "That's your own friend code")
		}
		k, x, y := friendKey(u.ID, o.ID)
		f := d.Friendships[k]
		switch {
		case f == nil:
			d.Friendships[k] = &Friendship{A: x, B: y, Requester: u.ID, Created: a.now()}
			result = "requested"
		case f.Accepted:
			result = "already_friends"
		case f.Requester == u.ID:
			result = "requested"
		default: // they already asked us: accept
			f.Accepted = true
			result = "accepted"
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": result})
}

func (a *API) acceptFriend(w http.ResponseWriter, r *http.Request, u *User, _ string) {
	id := r.PathValue("id")
	err := a.store.Write(func(d *Data) error {
		f := d.friendship(u.ID, id)
		if f == nil || f.Accepted || f.Requester == u.ID {
			return fail(http.StatusNotFound, "No friend request from that person")
		}
		f.Accepted = true
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *API) removeFriend(w http.ResponseWriter, r *http.Request, u *User, _ string) {
	id := r.PathValue("id")
	err := a.store.Write(func(d *Data) error {
		k, _, _ := friendKey(u.ID, id)
		if d.Friendships[k] == nil {
			return fail(http.StatusNotFound, "Not a friend")
		}
		delete(d.Friendships, k)
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- handlers: challenges

type standing struct {
	userView
	Total int `json:"total"`
	Today int `json:"today"`
}

type challengeView struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Start       string     `json:"start"`
	End         string     `json:"end"`
	CreatorID   string     `json:"creatorId"`
	CreatorName string     `json:"creatorName"`
	MyStatus    string     `json:"myStatus"`
	State       string     `json:"state"` // upcoming / active / finished
	Leaderboard []standing `json:"leaderboard"`
	Invited     []userView `json:"invited"`
}

func (a *API) viewChallenge(d *Data, c *Challenge, me, today string) challengeView {
	v := challengeView{ID: c.ID, Name: c.Name, Start: c.Start, End: c.End, CreatorID: c.Creator,
		MyStatus: c.Members[me], Leaderboard: []standing{}, Invited: []userView{}}
	if cu := d.Users[c.Creator]; cu != nil {
		v.CreatorName = cu.DisplayName
	}
	switch {
	case today < c.Start:
		v.State = "upcoming"
	case today > c.End:
		v.State = "finished"
	default:
		v.State = "active"
	}
	for id, status := range c.Members {
		mu := d.Users[id]
		if mu == nil {
			continue
		}
		if status == MemberJoined {
			s := standing{userView: publicView(mu), Total: sumSteps(mu, c.Start, c.End)}
			if v.State == "active" {
				s.Today = mu.Steps[today]
			}
			v.Leaderboard = append(v.Leaderboard, s)
		} else {
			v.Invited = append(v.Invited, publicView(mu))
		}
	}
	sort.Slice(v.Leaderboard, func(i, j int) bool {
		if v.Leaderboard[i].Total != v.Leaderboard[j].Total {
			return v.Leaderboard[i].Total > v.Leaderboard[j].Total
		}
		return v.Leaderboard[i].DisplayName < v.Leaderboard[j].DisplayName
	})
	return v
}

func (a *API) listChallenges(w http.ResponseWriter, r *http.Request, u *User, _ string) {
	today := a.clientToday(r)
	out := []challengeView{}
	a.store.Read(func(d *Data) {
		for _, c := range d.Challenges {
			if _, ok := c.Members[u.ID]; ok {
				out = append(out, a.viewChallenge(d, c, u.ID, today))
			}
		}
	})
	rank := map[string]int{"active": 0, "upcoming": 1, "finished": 2}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].State] != rank[out[j].State] {
			return rank[out[i].State] < rank[out[j].State]
		}
		return out[i].End > out[j].End
	})
	writeJSON(w, http.StatusOK, map[string]any{"challenges": out})
}

func (a *API) createChallenge(w http.ResponseWriter, r *http.Request, u *User, _ string) {
	var req struct {
		Name      string   `json:"name"`
		Start     string   `json:"start"`
		End       string   `json:"end"`
		MemberIDs []string `json:"memberIds"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	name := strings.TrimSpace(req.Name)
	if n := utf8.RuneCountInString(name); n < 1 || n > 60 {
		writeErr(w, fail(http.StatusBadRequest, "Challenge names must be 1–60 characters"))
		return
	}
	s, ok1 := parseDate(req.Start)
	e, ok2 := parseDate(req.End)
	if !ok1 || !ok2 || e.Before(s) {
		writeErr(w, fail(http.StatusBadRequest, "Pick a valid start and end date"))
		return
	}
	if e.Sub(s) > (maxChallengeDays-1)*24*time.Hour {
		writeErr(w, fail(http.StatusBadRequest, "Challenges can be at most 92 days long"))
		return
	}
	if len(req.MemberIDs) > maxMembers-1 {
		writeErr(w, fail(http.StatusBadRequest, "Too many people in one challenge (max 25)"))
		return
	}
	var view challengeView
	err := a.store.Write(func(d *Data) error {
		members := map[string]string{u.ID: MemberJoined}
		for _, id := range req.MemberIDs {
			if id == u.ID {
				continue
			}
			if !d.areFriends(u.ID, id) {
				return fail(http.StatusBadRequest, "You can only invite your friends")
			}
			members[id] = MemberInvited
		}
		c := &Challenge{ID: randomID(), Name: name, Creator: u.ID, Start: req.Start, End: req.End,
			Created: a.now(), Members: members}
		d.Challenges[c.ID] = c
		view = a.viewChallenge(d, c, u.ID, a.clientToday(r))
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

func (a *API) joinChallenge(w http.ResponseWriter, r *http.Request, u *User, _ string) {
	err := a.store.Write(func(d *Data) error {
		c := d.Challenges[r.PathValue("id")]
		if c == nil || c.Members[u.ID] == "" {
			return fail(http.StatusNotFound, "Challenge not found")
		}
		c.Members[u.ID] = MemberJoined
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *API) leaveChallenge(w http.ResponseWriter, r *http.Request, u *User, _ string) {
	err := a.store.Write(func(d *Data) error {
		c := d.Challenges[r.PathValue("id")]
		if c == nil || c.Members[u.ID] == "" {
			return fail(http.StatusNotFound, "Challenge not found")
		}
		delete(c.Members, u.ID)
		joined := 0
		for _, s := range c.Members {
			if s == MemberJoined {
				joined++
			}
		}
		if joined == 0 {
			delete(d.Challenges, c.ID)
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *API) deleteChallenge(w http.ResponseWriter, r *http.Request, u *User, _ string) {
	err := a.store.Write(func(d *Data) error {
		c := d.Challenges[r.PathValue("id")]
		if c == nil || c.Members[u.ID] == "" {
			return fail(http.StatusNotFound, "Challenge not found")
		}
		if c.Creator != u.ID {
			return fail(http.StatusForbidden, "Only the person who created a challenge can delete it")
		}
		delete(d.Challenges, c.ID)
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
