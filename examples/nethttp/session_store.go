package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	gociconnect "github.com/only1enes/goci-connect"
)

const (
	defaultSessionTTL = 10 * time.Minute
	sessionIDBytes    = 32
)

var (
	errSessionNotFound         = errors.New("authorization session not found")
	errSessionExpired          = errors.New("authorization session expired")
	errSessionProviderMismatch = errors.New("authorization session provider mismatch")
)

type pendingAuthorization struct {
	provider  string
	session   gociconnect.AuthorizationSession
	expiresAt time.Time
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]pendingAuthorization
	ttl      time.Duration
	random   io.Reader
	now      func() time.Time
}

func newSessionStore(ttl time.Duration) *sessionStore {
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	return &sessionStore{
		sessions: make(map[string]pendingAuthorization),
		ttl:      ttl,
		random:   rand.Reader,
		now:      time.Now,
	}
}

func (store *sessionStore) create(provider string, session gociconnect.AuthorizationSession) (string, time.Time, error) {
	now := store.now()
	expiresAt := now.Add(store.ttl)
	for range 4 {
		buffer := make([]byte, sessionIDBytes)
		if _, err := io.ReadFull(store.random, buffer); err != nil {
			return "", time.Time{}, err
		}
		id := base64.RawURLEncoding.EncodeToString(buffer)
		store.mu.Lock()
		store.removeExpired(now)
		if _, exists := store.sessions[id]; !exists {
			store.sessions[id] = pendingAuthorization{
				provider:  strings.TrimSpace(provider),
				session:   session,
				expiresAt: expiresAt,
			}
			store.mu.Unlock()
			return id, expiresAt, nil
		}
		store.mu.Unlock()
	}
	return "", time.Time{}, errors.New("could not allocate an authorization session")
}

func (store *sessionStore) consume(id, provider string) (gociconnect.AuthorizationSession, error) {
	store.mu.Lock()
	pending, exists := store.sessions[id]
	if exists {
		delete(store.sessions, id)
	}
	store.mu.Unlock()
	if !exists {
		return gociconnect.AuthorizationSession{}, errSessionNotFound
	}
	if !pending.expiresAt.After(store.now()) {
		return gociconnect.AuthorizationSession{}, errSessionExpired
	}
	if pending.provider != strings.TrimSpace(provider) {
		return gociconnect.AuthorizationSession{}, errSessionProviderMismatch
	}
	return pending.session, nil
}

func (store *sessionStore) removeExpired(now time.Time) {
	for id, pending := range store.sessions {
		if !pending.expiresAt.After(now) {
			delete(store.sessions, id)
		}
	}
}
