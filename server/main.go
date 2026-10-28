// Feynos Fit friends & challenges server.
//
// One small binary with no third-party dependencies. It stores accounts, friend links, daily
// step totals and challenges in a single JSON file under DATA_DIR. Only step totals and
// display names are ever sent here; food, weight and health data stay on the phone.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

var version = "1.0.0"

const adminAddr = "127.0.0.1:8096" // reachable only from inside the container

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	switch strings.ToLower(env(key, "")) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "healthcheck":
		err = healthcheck()
	case "version":
		fmt.Println(version)
	case "signup-code", "users", "reset-password", "delete-user", "new-signup-code":
		err = adminCommand(cmd, os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`feynos-server ` + version + `

Commands (run with: docker exec feynos-fit-server /feynos-server <command>):
  signup-code              show the invite code new users need to sign up
  new-signup-code          replace the invite code with a new random one
  users                    list accounts
  reset-password <user>    set a new random password and sign the user out everywhere
  delete-user <user>       delete an account and all of its data
  version                  show the server version
`)
}

// ---------------------------------------------------------------- server

func serve() error {
	dataDir := env("DATA_DIR", "/data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	store, err := OpenStore(filepath.Join(dataDir, "feynos-fit.json"))
	if err != nil {
		return err
	}

	// Invite code: SIGNUP_CODE if set, otherwise a random one kept in the data file.
	err = store.Write(func(d *Data) error {
		if c := strings.ToUpper(env("SIGNUP_CODE", "")); c != "" {
			d.SignupCode = c
		} else if d.SignupCode == "" {
			d.SignupCode = randomCode(10)
		}
		d.prune(time.Now())
		return nil
	})
	if err != nil {
		return err
	}

	cfg := Config{AllowSignup: envBool("ALLOW_SIGNUP", true), TrustProxy: envBool("TRUST_PROXY", false)}
	api := NewAPI(store, cfg)

	adminToken := randomToken()
	tokenFile := filepath.Join(dataDir, "admin.token")
	if err := os.WriteFile(tokenFile, []byte(adminToken), 0o600); err != nil {
		return err
	}

	addr := env("LISTEN_ADDR", ":8095")
	srv := &http.Server{
		Addr:              addr,
		Handler:           api.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	admin := &http.Server{Addr: adminAddr, Handler: adminRoutes(store, adminToken), ReadHeaderTimeout: 5 * time.Second}

	// Hourly housekeeping.
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = store.Write(func(d *Data) error { d.prune(time.Now()); return nil })
				api.authIP.Sweep()
				api.failUser.Sweep()
				api.friendIP.Sweep()
			case <-stop:
				return
			}
		}
	}()

	errc := make(chan error, 2)
	go func() { errc <- srv.ListenAndServe() }()
	go func() { errc <- admin.ListenAndServe() }()

	var code string
	var users int
	store.Read(func(d *Data) { code, users = d.SignupCode, len(d.Users) })
	log.Printf("Feynos Fit server %s listening on %s (%d accounts)", version, addr, users)
	if cfg.AllowSignup {
		log.Printf("Invite code for new accounts: %s", code)
	} else {
		log.Printf("Sign-ups are turned off (ALLOW_SIGNUP=false)")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Printf("shutting down (%s)", s)
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	close(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = admin.Shutdown(ctx)
	return srv.Shutdown(ctx)
}

func healthcheck() error {
	addr := env("LISTEN_ADDR", ":8095")
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := http.Client{Timeout: 4 * time.Second}
	resp, err := c.Get("http://" + addr + "/api/v1/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health returned %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------- admin (container-local)

func adminRoutes(store *Store, token string) http.Handler {
	m := http.NewServeMux()
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !constantEqual(r.Header.Get("X-Admin-Token"), token) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			h(w, r)
		}
	}
	findUser := func(d *Data, name string) *User { return d.userByName(strings.ToLower(strings.TrimSpace(name))) }

	m.HandleFunc("GET /signup-code", guard(func(w http.ResponseWriter, r *http.Request) {
		store.Read(func(d *Data) { writeJSON(w, 200, map[string]string{"code": d.SignupCode}) })
	}))
	m.HandleFunc("POST /new-signup-code", guard(func(w http.ResponseWriter, r *http.Request) {
		var code string
		_ = store.Write(func(d *Data) error { d.SignupCode = randomCode(10); code = d.SignupCode; return nil })
		writeJSON(w, 200, map[string]string{"code": code})
	}))
	m.HandleFunc("GET /users", guard(func(w http.ResponseWriter, r *http.Request) {
		type row struct {
			Username, DisplayName string
			Created               time.Time
			Friends               int
		}
		var rows []row
		store.Read(func(d *Data) {
			for _, u := range d.Users {
				n := 0
				for _, f := range d.Friendships {
					if f.Accepted && (f.A == u.ID || f.B == u.ID) {
						n++
					}
				}
				rows = append(rows, row{u.Username, u.DisplayName, u.Created, n})
			}
		})
		sort.Slice(rows, func(i, j int) bool { return rows[i].Username < rows[j].Username })
		writeJSON(w, 200, rows)
	}))
	m.HandleFunc("POST /reset-password", guard(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Username string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		pw := randomCode(12)
		hash, err := hashPassword(pw)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		err = store.Write(func(d *Data) error {
			u := findUser(d, req.Username)
			if u == nil {
				return errors.New("no such user")
			}
			u.PassHash = hash
			for k, s := range d.Sessions {
				if s.UserID == u.ID {
					delete(d.Sessions, k)
				}
			}
			return nil
		})
		if err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		writeJSON(w, 200, map[string]string{"password": pw})
	}))
	m.HandleFunc("POST /delete-user", guard(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Username string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		err := store.Write(func(d *Data) error {
			u := findUser(d, req.Username)
			if u == nil {
				return errors.New("no such user")
			}
			d.deleteUser(u.ID)
			return nil
		})
		if err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	return m
}

func adminCommand(cmd string, args []string) error {
	token, err := os.ReadFile(filepath.Join(env("DATA_DIR", "/data"), "admin.token"))
	if err != nil {
		return fmt.Errorf("is the server running? (%w)", err)
	}
	call := func(method, path string, body any) ([]byte, error) {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, "http://"+adminAddr+path, rd)
		req.Header.Set("X-Admin-Token", strings.TrimSpace(string(token)))
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			return nil, fmt.Errorf("is the server running? (%w)", err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			return nil, errors.New(strings.TrimSpace(string(out)))
		}
		return out, nil
	}
	needUser := func() (string, error) {
		if len(args) != 1 {
			return "", fmt.Errorf("usage: %s <username>", cmd)
		}
		return args[0], nil
	}

	switch cmd {
	case "signup-code", "new-signup-code":
		method, path := "GET", "/signup-code"
		if cmd == "new-signup-code" {
			method, path = "POST", "/new-signup-code"
		}
		out, err := call(method, path, nil)
		if err != nil {
			return err
		}
		var v struct{ Code string }
		_ = json.Unmarshal(out, &v)
		fmt.Println(v.Code)
	case "users":
		out, err := call("GET", "/users", nil)
		if err != nil {
			return err
		}
		var rows []struct {
			Username, DisplayName string
			Created               time.Time
			Friends               int
		}
		_ = json.Unmarshal(out, &rows)
		if len(rows) == 0 {
			fmt.Println("No accounts yet.")
		}
		for _, r := range rows {
			fmt.Printf("%-24s %-24s friends:%-3d joined %s\n", r.Username, r.DisplayName, r.Friends, r.Created.Format("2006-01-02"))
		}
	case "reset-password":
		u, err := needUser()
		if err != nil {
			return err
		}
		out, err := call("POST", "/reset-password", map[string]string{"username": u})
		if err != nil {
			return err
		}
		var v struct{ Password string }
		_ = json.Unmarshal(out, &v)
		fmt.Printf("New password for %s: %s\n(they've been signed out on all devices)\n", u, v.Password)
	case "delete-user":
		u, err := needUser()
		if err != nil {
			return err
		}
		if _, err := call("POST", "/delete-user", map[string]string{"username": u}); err != nil {
			return err
		}
		fmt.Printf("Deleted %s and all of their data.\n", u)
	}
	return nil
}
