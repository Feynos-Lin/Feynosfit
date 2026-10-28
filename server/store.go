package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// All data lives in one JSON file. A friends-and-family server holds a few kilobytes,
// so a mutex-protected in-memory copy with atomic writes is simpler and safer than a database.

type User struct {
	ID          string         `json:"id"`
	Username    string         `json:"username"`
	DisplayName string         `json:"displayName"`
	PassHash    string         `json:"passHash"`
	FriendCode  string         `json:"friendCode"`
	Created     time.Time      `json:"created"`
	Steps       map[string]int `json:"steps"` // "YYYY-MM-DD" -> steps
	StepsUpdate time.Time      `json:"stepsUpdated"`
}

type Session struct {
	UserID  string    `json:"userId"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}

type Friendship struct {
	A         string    `json:"a"` // lower user id
	B         string    `json:"b"` // higher user id
	Requester string    `json:"requester"`
	Accepted  bool      `json:"accepted"`
	Created   time.Time `json:"created"`
}

const (
	MemberInvited = "invited"
	MemberJoined  = "joined"
)

type Challenge struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Creator string            `json:"creator"`
	Start   string            `json:"start"` // inclusive local date
	End     string            `json:"end"`   // inclusive local date
	Created time.Time         `json:"created"`
	Members map[string]string `json:"members"` // user id -> invited/joined
}

type Data struct {
	Version     int                    `json:"version"`
	SignupCode  string                 `json:"signupCode"`
	Users       map[string]*User       `json:"users"`
	Sessions    map[string]*Session    `json:"sessions"` // key: sha256(token) hex
	Friendships map[string]*Friendship `json:"friendships"`
	Challenges  map[string]*Challenge  `json:"challenges"`

	// Web admin panel
	AdminPassHash  string `json:"adminPassHash,omitempty"`
	AdminSetupCode string `json:"adminSetupCode,omitempty"` // needed once, to create the admin password
	SignupOpen     *bool  `json:"signupOpen,omitempty"`     // set from the panel; overrides ALLOW_SIGNUP
}

type Store struct {
	mu   sync.RWMutex
	path string
	d    *Data
}

func newData() *Data {
	return &Data{
		Version:     1,
		Users:       map[string]*User{},
		Sessions:    map[string]*Session{},
		Friendships: map[string]*Friendship{},
		Challenges:  map[string]*Challenge{},
	}
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, d: newData()}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, s.saveLocked()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s.d); err != nil {
		return nil, fmt.Errorf("data file %s is corrupt: %w", path, err)
	}
	if s.d.Users == nil {
		s.d.Users = map[string]*User{}
	}
	if s.d.Sessions == nil {
		s.d.Sessions = map[string]*Session{}
	}
	if s.d.Friendships == nil {
		s.d.Friendships = map[string]*Friendship{}
	}
	if s.d.Challenges == nil {
		s.d.Challenges = map[string]*Challenge{}
	}
	for _, u := range s.d.Users {
		if u.Steps == nil {
			u.Steps = map[string]int{}
		}
	}
	return s, nil
}

// Read runs fn with a read lock.
func (s *Store) Read(fn func(d *Data)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(s.d)
}

// Write runs fn with the write lock and saves if fn returns nil.
func (s *Store) Write(fn func(d *Data) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(s.d); err != nil {
		return err
	}
	return s.saveLocked()
}

// saveLocked writes atomically: temp file, fsync, rename. Caller holds the lock.
func (s *Store) saveLocked() error {
	b, err := json.Marshal(s.d)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".feynos-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

// ---- helpers used under a lock ----

func friendKey(x, y string) (string, string, string) {
	if x > y {
		x, y = y, x
	}
	return x + ":" + y, x, y
}

func (d *Data) friendship(x, y string) *Friendship {
	k, _, _ := friendKey(x, y)
	return d.Friendships[k]
}

func (d *Data) areFriends(x, y string) bool {
	f := d.friendship(x, y)
	return f != nil && f.Accepted
}

func (d *Data) userByName(name string) *User {
	for _, u := range d.Users {
		if u.Username == name {
			return u
		}
	}
	return nil
}

func (d *Data) userByFriendCode(code string) *User {
	for _, u := range d.Users {
		if u.FriendCode == code {
			return u
		}
	}
	return nil
}

func (d *Data) sessionsOf(userID string) []string {
	var keys []string
	for k, s := range d.Sessions {
		if s.UserID == userID {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return d.Sessions[keys[i]].Created.Before(d.Sessions[keys[j]].Created) })
	return keys
}

func (d *Data) deleteUser(id string) {
	delete(d.Users, id)
	for k, s := range d.Sessions {
		if s.UserID == id {
			delete(d.Sessions, k)
		}
	}
	for k, f := range d.Friendships {
		if f.A == id || f.B == id {
			delete(d.Friendships, k)
		}
	}
	for cid, c := range d.Challenges {
		if c.Creator == id {
			delete(d.Challenges, cid)
			continue
		}
		delete(c.Members, id)
	}
}

// prune drops expired sessions, old step history and long-finished challenges.
func (d *Data) prune(now time.Time) {
	for k, s := range d.Sessions {
		if now.After(s.Expires) {
			delete(d.Sessions, k)
		}
	}
	cutoff := now.AddDate(0, 0, -400).Format(dateLayout)
	for _, u := range d.Users {
		for day := range u.Steps {
			if day < cutoff {
				delete(u.Steps, day)
			}
		}
	}
	oldEnd := now.AddDate(0, 0, -180).Format(dateLayout)
	for id, c := range d.Challenges {
		if c.End < oldEnd {
			delete(d.Challenges, id)
		}
	}
}
