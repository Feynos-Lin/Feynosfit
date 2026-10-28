package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type tc struct {
	t   *testing.T
	srv *httptest.Server
	api *API
	dir string
}

func newTC(t *testing.T) *tc {
	t.Helper()
	dir := t.TempDir()
	st, err := OpenStore(filepath.Join(dir, "data.json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Write(func(d *Data) error { d.SignupCode = "INVITE2026"; return nil })
	api := NewAPI(st, Config{AllowSignup: true})
	api.now = func() time.Time { return time.Date(2026, 10, 27, 18, 0, 0, 0, time.UTC) }
	srv := httptest.NewServer(api.Routes())
	t.Cleanup(srv.Close)
	return &tc{t: t, srv: srv, api: api, dir: dir}
}

func (c *tc) do(method, path, token string, body any) (int, map[string]any) {
	c.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (c *tc) register(user, display string) (token, id, code string) {
	c.t.Helper()
	st, out := c.do("POST", "/api/v1/register", "", map[string]string{
		"username": user, "password": "correct horse", "displayName": display, "signupCode": "invite2026"})
	if st != 201 {
		c.t.Fatalf("register %s: %d %v", user, st, out)
	}
	u := out["user"].(map[string]any)
	return out["token"].(string), u["id"].(string), u["friendCode"].(string)
}

func expect(t *testing.T, got, want int, what string, body map[string]any) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %d want %d (%v)", what, got, want, body)
	}
}

func TestSignupNeedsInviteCodeAndValidInput(t *testing.T) {
	c := newTC(t)
	st, b := c.do("POST", "/api/v1/register", "", map[string]string{"username": "amy", "password": "correct horse", "displayName": "Amy", "signupCode": "WRONG"})
	expect(t, st, 403, "wrong invite code", b)
	st, b = c.do("POST", "/api/v1/register", "", map[string]string{"username": "amy", "password": "short", "displayName": "Amy", "signupCode": "INVITE2026"})
	expect(t, st, 400, "short password", b)
	st, b = c.do("POST", "/api/v1/register", "", map[string]string{"username": "a!", "password": "correct horse", "displayName": "Amy", "signupCode": "INVITE2026"})
	expect(t, st, 400, "bad username", b)
	c.register("amy", "Amy")
	st, b = c.do("POST", "/api/v1/register", "", map[string]string{"username": "AMY", "password": "correct horse", "displayName": "Amy 2", "signupCode": "INVITE2026"})
	expect(t, st, 409, "duplicate username (case-insensitive)", b)
}

func TestSignupCanBeDisabled(t *testing.T) {
	c := newTC(t)
	c.api.cfg.AllowSignup = false
	st, b := c.do("POST", "/api/v1/register", "", map[string]string{"username": "amy", "password": "correct horse", "displayName": "Amy", "signupCode": "INVITE2026"})
	expect(t, st, 403, "signup disabled", b)
}

func TestLoginLogoutAndLockout(t *testing.T) {
	c := newTC(t)
	c.register("amy", "Amy")
	st, b := c.do("POST", "/api/v1/login", "", map[string]string{"username": "Amy", "password": "correct horse"})
	expect(t, st, 200, "login", b)
	tok := b["token"].(string)
	if st, b := c.do("GET", "/api/v1/me", tok, nil); st != 200 || b["username"] != "amy" {
		t.Fatalf("me: %d %v", st, b)
	}
	st, b = c.do("POST", "/api/v1/login", "", map[string]string{"username": "nobody", "password": "x"})
	expect(t, st, 401, "unknown user", b)
	if b["error"] != "Wrong username or password" {
		t.Fatalf("unknown user should get the generic message, got %v", b)
	}
	expect2, _ := c.do("POST", "/api/v1/logout", tok, nil)
	expect(t, expect2, 200, "logout", nil)
	st, b = c.do("GET", "/api/v1/me", tok, nil)
	expect(t, st, 401, "token after logout", b)

	for i := 0; i < 10; i++ {
		c.do("POST", "/api/v1/login", "", map[string]string{"username": "amy", "password": "wrong password"})
	}
	st, b = c.do("POST", "/api/v1/login", "", map[string]string{"username": "amy", "password": "correct horse"})
	expect(t, st, 429, "locked after 10 failures even with right password", b)
}

func TestIPRateLimit(t *testing.T) {
	c := newTC(t)
	last := 0
	for i := 0; i < 31; i++ {
		last, _ = c.do("POST", "/api/v1/login", "", map[string]string{"username": "u" + string(rune('a'+i%26)), "password": "x"})
	}
	expect(t, last, 429, "31st auth request from one IP", nil)
}

func TestRequiresAuth(t *testing.T) {
	c := newTC(t)
	for _, p := range [][2]string{{"GET", "/api/v1/me"}, {"GET", "/api/v1/friends"}, {"PUT", "/api/v1/steps"}, {"GET", "/api/v1/challenges"}} {
		st, b := c.do(p[0], p[1], "", nil)
		expect(t, st, 401, p[1]+" without token", b)
		st, b = c.do(p[0], p[1], "forged-token", nil)
		expect(t, st, 401, p[1]+" with forged token", b)
	}
}

func TestStepsValidation(t *testing.T) {
	c := newTC(t)
	tok, _, _ := c.register("amy", "Amy")
	day := func(d string, n int) map[string]any {
		return map[string]any{"days": []map[string]any{{"date": d, "steps": n}}}
	}
	st, b := c.do("PUT", "/api/v1/steps", tok, day("2026-10-27", 8000))
	expect(t, st, 200, "valid steps", b)
	st, b = c.do("PUT", "/api/v1/steps", tok, day("2026-10-28", 10))
	expect(t, st, 200, "tomorrow in UTC is allowed (time zones)", b)
	st, b = c.do("PUT", "/api/v1/steps", tok, day("2026-11-05", 10))
	expect(t, st, 400, "far future", b)
	st, b = c.do("PUT", "/api/v1/steps", tok, day("2025-01-01", 10))
	expect(t, st, 400, "too old", b)
	st, b = c.do("PUT", "/api/v1/steps", tok, day("2026-10-27", 500000))
	expect(t, st, 400, "implausible count", b)
	st, b = c.do("PUT", "/api/v1/steps", tok, day("2026-13-01", 10))
	expect(t, st, 400, "bad date", b)
}

func TestFriendsFlowAndPrivacy(t *testing.T) {
	c := newTC(t)
	amy, amyID, _ := c.register("amy", "Amy")
	ben, benID, benCode := c.register("ben", "Ben")
	cat, _, _ := c.register("cat", "Cat")

	c.do("PUT", "/api/v1/steps", ben, map[string]any{"days": []map[string]any{{"date": "2026-10-27", "steps": 12000}, {"date": "2026-10-22", "steps": 3000}}})

	// Own code and unknown code are rejected.
	_, _, amyCode := c.register("dan", "Dan")
	_ = amyCode
	st, b := c.do("POST", "/api/v1/friends", amy, map[string]string{"code": "ZZZZZZZZ"})
	expect(t, st, 404, "unknown friend code", b)

	st, b = c.do("POST", "/api/v1/friends", amy, map[string]string{"code": strings.ToLower(benCode[:4]) + "-" + benCode[4:]})
	expect(t, st, 200, "add by code (case/dash tolerant)", b)
	if b["result"] != "requested" {
		t.Fatalf("want requested, got %v", b)
	}
	// Pending: Amy cannot see Ben's steps yet.
	_, b = c.do("GET", "/api/v1/friends?today=2026-10-27", amy, nil)
	if len(b["friends"].([]any)) != 0 || len(b["outgoing"].([]any)) != 1 {
		t.Fatalf("pending request leaked data: %v", b)
	}
	// Amy cannot accept her own request.
	st, _ = c.do("POST", "/api/v1/friends/"+benID+"/accept", amy, nil)
	expect(t, st, 404, "accept own request", nil)
	// Ben accepts.
	_, b = c.do("GET", "/api/v1/friends", ben, nil)
	if len(b["incoming"].([]any)) != 1 {
		t.Fatalf("ben should see incoming: %v", b)
	}
	st, _ = c.do("POST", "/api/v1/friends/"+amyID+"/accept", ben, nil)
	expect(t, st, 200, "accept", nil)
	_, b = c.do("GET", "/api/v1/friends?today=2026-10-27", amy, nil)
	fr := b["friends"].([]any)
	if len(fr) != 1 {
		t.Fatalf("amy should have 1 friend: %v", b)
	}
	f := fr[0].(map[string]any)
	if f["today"].(float64) != 12000 || f["week"].(float64) != 15000 {
		t.Fatalf("friend steps wrong: %v", f)
	}
	if _, leaked := f["friendCode"]; leaked {
		t.Fatalf("friend code of others must not be exposed: %v", f)
	}
	// Cat (not a friend) sees nothing of Ben.
	_, b = c.do("GET", "/api/v1/friends", cat, nil)
	if len(b["friends"].([]any)) != 0 {
		t.Fatalf("non-friend sees data: %v", b)
	}
	// Remove friend.
	st, _ = c.do("DELETE", "/api/v1/friends/"+benID, amy, nil)
	expect(t, st, 200, "unfriend", nil)
	_, b = c.do("GET", "/api/v1/friends", amy, nil)
	if len(b["friends"].([]any)) != 0 {
		t.Fatalf("unfriend failed: %v", b)
	}
}

func TestMutualRequestAutoAccepts(t *testing.T) {
	c := newTC(t)
	amy, _, amyCode := c.register("amy", "Amy")
	ben, _, benCode := c.register("ben", "Ben")
	c.do("POST", "/api/v1/friends", amy, map[string]string{"code": benCode})
	_, b := c.do("POST", "/api/v1/friends", ben, map[string]string{"code": amyCode})
	if b["result"] != "accepted" {
		t.Fatalf("mutual add should accept: %v", b)
	}
}

func TestChallenges(t *testing.T) {
	c := newTC(t)
	amy, amyID, _ := c.register("amy", "Amy")
	ben, benID, benCode := c.register("ben", "Ben")
	cat, catID, _ := c.register("cat", "Cat")
	c.do("POST", "/api/v1/friends", amy, map[string]string{"code": benCode})
	c.do("POST", "/api/v1/friends/"+amyID+"/accept", ben, nil)

	steps := func(tok string, n1, n2 int) {
		c.do("PUT", "/api/v1/steps", tok, map[string]any{"days": []map[string]any{
			{"date": "2026-10-26", "steps": n1}, {"date": "2026-10-27", "steps": n2}, {"date": "2026-10-20", "steps": 99999}}})
	}
	steps(amy, 5000, 6000)
	steps(ben, 9000, 4000)

	st, b := c.do("POST", "/api/v1/challenges", amy, map[string]any{"name": "Week race", "start": "2026-10-26", "end": "2026-11-01", "memberIds": []string{catID}})
	expect(t, st, 400, "invite non-friend", b)
	st, b = c.do("POST", "/api/v1/challenges", amy, map[string]any{"name": "Long", "start": "2026-01-01", "end": "2026-12-31"})
	expect(t, st, 400, "too long", b)
	st, b = c.do("POST", "/api/v1/challenges", amy, map[string]any{"name": "Week race", "start": "2026-10-26", "end": "2026-11-01", "memberIds": []string{benID}})
	expect(t, st, 201, "create", b)
	id := b["id"].(string)

	// Ben is invited, not yet on the board.
	_, b = c.do("GET", "/api/v1/challenges?today=2026-10-27", ben, nil)
	ch := b["challenges"].([]any)[0].(map[string]any)
	if ch["myStatus"] != "invited" || len(ch["leaderboard"].([]any)) != 1 || ch["state"] != "active" {
		t.Fatalf("before join: %v", ch)
	}
	// Cat can't see or join it.
	_, b = c.do("GET", "/api/v1/challenges", cat, nil)
	if len(b["challenges"].([]any)) != 0 {
		t.Fatalf("outsider sees challenge: %v", b)
	}
	st, _ = c.do("POST", "/api/v1/challenges/"+id+"/join", cat, nil)
	expect(t, st, 404, "outsider join", nil)

	st, _ = c.do("POST", "/api/v1/challenges/"+id+"/join", ben, nil)
	expect(t, st, 200, "join", nil)
	_, b = c.do("GET", "/api/v1/challenges?today=2026-10-27", amy, nil)
	lb := b["challenges"].([]any)[0].(map[string]any)["leaderboard"].([]any)
	first, second := lb[0].(map[string]any), lb[1].(map[string]any)
	if first["displayName"] != "Ben" || first["total"].(float64) != 13000 || second["total"].(float64) != 11000 {
		t.Fatalf("leaderboard wrong (steps outside range must not count): %v", lb)
	}
	if first["today"].(float64) != 4000 {
		t.Fatalf("today wrong: %v", first)
	}

	st, _ = c.do("DELETE", "/api/v1/challenges/"+id, ben, nil)
	expect(t, st, 403, "non-creator delete", nil)
	st, _ = c.do("POST", "/api/v1/challenges/"+id+"/leave", ben, nil)
	expect(t, st, 200, "leave", nil)
	st, _ = c.do("DELETE", "/api/v1/challenges/"+id, amy, nil)
	expect(t, st, 200, "creator delete", nil)
}

func TestDeleteAccountRemovesEverything(t *testing.T) {
	c := newTC(t)
	amy, amyID, _ := c.register("amy", "Amy")
	ben, _, benCode := c.register("ben", "Ben")
	c.do("POST", "/api/v1/friends", amy, map[string]string{"code": benCode})
	st, _ := c.do("POST", "/api/v1/me/delete", amy, map[string]string{"password": "wrong"})
	expect(t, st, 403, "delete with wrong password", nil)
	st, _ = c.do("POST", "/api/v1/me/delete", amy, map[string]string{"password": "correct horse"})
	expect(t, st, 200, "delete", nil)
	st, _ = c.do("GET", "/api/v1/me", amy, nil)
	expect(t, st, 401, "deleted user's token", nil)
	_, b := c.do("GET", "/api/v1/friends", ben, nil)
	if len(b["incoming"].([]any)) != 0 {
		t.Fatalf("dangling request: %v", b)
	}
	c.api.store.Read(func(d *Data) {
		if d.Users[amyID] != nil {
			t.Fatal("user still stored")
		}
	})
}

func TestPasswordChangeSignsOutOtherDevices(t *testing.T) {
	c := newTC(t)
	tok1, _, _ := c.register("amy", "Amy")
	_, b := c.do("POST", "/api/v1/login", "", map[string]string{"username": "amy", "password": "correct horse"})
	tok2 := b["token"].(string)
	st, _ := c.do("POST", "/api/v1/me/password", tok1, map[string]string{"current": "correct horse", "new": "battery staple"})
	expect(t, st, 200, "change password", nil)
	if st, _ := c.do("GET", "/api/v1/me", tok2, nil); st != 401 {
		t.Fatal("other device should be signed out")
	}
	if st, _ := c.do("GET", "/api/v1/me", tok1, nil); st != 200 {
		t.Fatal("current device should stay signed in")
	}
	st, _ = c.do("POST", "/api/v1/login", "", map[string]string{"username": "amy", "password": "battery staple"})
	expect(t, st, 200, "login with new password", nil)
}

func TestPersistsAcrossRestart(t *testing.T) {
	c := newTC(t)
	tok, _, _ := c.register("amy", "Amy")
	c.do("PUT", "/api/v1/steps", tok, map[string]any{"days": []map[string]any{{"date": "2026-10-27", "steps": 4321}}})
	st, err := OpenStore(filepath.Join(c.dir, "data.json"))
	if err != nil {
		t.Fatal(err)
	}
	st.Read(func(d *Data) {
		u := d.userByName("amy")
		if u == nil || u.Steps["2026-10-27"] != 4321 {
			t.Fatalf("not persisted: %+v", u)
		}
		for _, s := range d.Sessions {
			_ = s
		}
		for k := range d.Sessions {
			if k == tok {
				t.Fatal("raw token must never be stored")
			}
		}
	})
}

func TestBodyLimitAndHeaders(t *testing.T) {
	c := newTC(t)
	big := strings.Repeat("a", 70<<10)
	resp, err := http.Post(c.srv.URL+"/api/v1/login", "application/json", strings.NewReader(`{"username":"`+big+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("oversized body: %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("security headers missing")
	}
}

func TestPasswordHashing(t *testing.T) {
	h, err := hashPassword("secret password")
	if err != nil {
		t.Fatal(err)
	}
	if !checkPassword(h, "secret password") || checkPassword(h, "secret passworD") || checkPassword("garbage", "x") {
		t.Fatal("password check broken")
	}
	h2, _ := hashPassword("secret password")
	if h == h2 {
		t.Fatal("salts must differ")
	}
}

func TestRenameViaPost(t *testing.T) {
	c := newTC(t)
	tok, _, _ := c.register("amy", "Amy")
	st, b := c.do("POST", "/api/v1/me", tok, map[string]string{"displayName": "Amy R"})
	expect(t, st, 200, "rename via POST", b)
	if b["displayName"] != "Amy R" {
		t.Fatalf("rename: %v", b)
	}
	st, b = c.do("POST", "/api/v1/me", tok, map[string]string{"displayName": "   "})
	expect(t, st, 400, "blank display name", b)
}
