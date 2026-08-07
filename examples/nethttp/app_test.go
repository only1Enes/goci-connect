package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gociconnect "github.com/only1enes/goci-connect"
	"github.com/only1enes/goci-connect/testkit"
)

func TestIndexWorksWithOneProvider(t *testing.T) {
	app, _, _ := newTestApplication(t, false, nil)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "/auth/fake") || !strings.Contains(response.Body.String(), "Continue with fake") {
		t.Fatalf("index response = %d, %s", response.Code, response.Body.String())
	}
}

func TestRedirectCreatesOpaqueServerSideSessionCookie(t *testing.T) {
	app, provider, store := newTestApplication(t, true, nil)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/auth/fake", nil))
	if response.Code != http.StatusFound || response.Header().Get("Location") != "https://provider.example/authorize?state=provider-state" {
		t.Fatalf("redirect response = %d, location %q", response.Code, response.Header().Get("Location"))
	}
	cookie := response.Result().Cookies()[0]
	if cookie.Name != sessionCookieName || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/auth/" {
		t.Fatalf("session cookie = %+v", cookie)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(decoded) != sessionIDBytes {
		t.Fatalf("opaque session ID = %q, decoded bytes = %d, error = %v", cookie.Value, len(decoded), err)
	}
	for _, forbidden := range []string{"provider-state", "provider-verifier", "access-token", "refresh-token"} {
		if strings.Contains(cookie.Value, forbidden) {
			t.Fatalf("cookie exposes %q: %q", forbidden, cookie.Value)
		}
	}
	store.mu.Lock()
	pending, exists := store.sessions[cookie.Value]
	store.mu.Unlock()
	if !exists || pending.provider != "fake" || pending.session.State != "provider-state" || pending.session.PKCEVerifier != "provider-verifier" {
		t.Fatalf("stored authorization session = %+v, exists = %t", pending, exists)
	}
	if provider.BeginCallCount() != 1 {
		t.Fatalf("BeginCallCount() = %d", provider.BeginCallCount())
	}
}

func TestCallbackCompletesOnceWithoutRenderingTokens(t *testing.T) {
	app, provider, _ := newTestApplication(t, false, nil)
	cookie := beginFlow(t, app)
	response := callback(t, app, cookie, "/auth/fake/callback?code=callback-code&state=provider-state")
	if response.Code != http.StatusOK {
		t.Fatalf("callback response = %d, %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, visible := range []string{"Authentication complete", "Example User", "example-login", "user@example.com"} {
		if !strings.Contains(body, visible) {
			t.Fatalf("callback response omits %q: %s", visible, body)
		}
	}
	for _, secret := range []string{"browser-access-token", "browser-refresh-token", "callback-code", "provider-verifier"} {
		if strings.Contains(body, secret) {
			t.Fatalf("callback response exposes %q: %s", secret, body)
		}
	}
	calls := provider.CompleteCalls()
	if len(calls) != 1 || calls[0].Callback.Code != "callback-code" || calls[0].Callback.State != "provider-state" || calls[0].Session.State != "provider-state" || calls[0].Session.PKCEVerifier != "provider-verifier" {
		t.Fatalf("CompleteCalls() = %+v", calls)
	}
	cleared := response.Result().Cookies()[0]
	if cleared.Name != sessionCookieName || cleared.MaxAge != -1 || cleared.Value != "" {
		t.Fatalf("cleared cookie = %+v", cleared)
	}

	replay := callback(t, app, cookie, "/auth/fake/callback?code=replayed-code&state=provider-state")
	if replay.Code != http.StatusBadRequest || provider.CompleteCallCount() != 1 || !strings.Contains(replay.Body.String(), "already been used") {
		t.Fatalf("replay response = %d, %s, complete calls = %d", replay.Code, replay.Body.String(), provider.CompleteCallCount())
	}
}

func TestCallbackWithoutSession(t *testing.T) {
	app, provider, _ := newTestApplication(t, false, nil)
	response := callback(t, app, nil, "/auth/fake/callback?code=callback-code&state=provider-state")
	if response.Code != http.StatusBadRequest || provider.CompleteCallCount() != 0 || !strings.Contains(response.Body.String(), "session is missing") {
		t.Fatalf("response = %d, %s, complete calls = %d", response.Code, response.Body.String(), provider.CompleteCallCount())
	}
}

func TestExpiredSession(t *testing.T) {
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	app, provider, store := newTestApplication(t, false, &now)
	cookie := beginFlow(t, app)
	now = now.Add(store.ttl + time.Second)
	response := callback(t, app, cookie, "/auth/fake/callback?code=callback-code&state=provider-state")
	if response.Code != http.StatusBadRequest || provider.CompleteCallCount() != 0 || !strings.Contains(response.Body.String(), "session has expired") {
		t.Fatalf("response = %d, %s, complete calls = %d", response.Code, response.Body.String(), provider.CompleteCallCount())
	}
	replay := callback(t, app, cookie, "/auth/fake/callback?code=callback-code&state=provider-state")
	if replay.Code != http.StatusBadRequest || !strings.Contains(replay.Body.String(), "already been used") {
		t.Fatalf("expired replay response = %d, %s", replay.Code, replay.Body.String())
	}
}

func TestProviderCallbackErrorConsumesSessionAndHidesDetails(t *testing.T) {
	var logs bytes.Buffer
	app, provider, _ := newTestApplication(t, false, nil)
	app.logger = log.New(&logs, "", 0)
	provider.ConfigureComplete(gociconnect.User{}, gociconnect.NewError(
		gociconnect.ErrorCodeAuthorizationDenied,
		"fake",
		"complete authorization",
		errors.New("provider-description-secret"),
	))
	cookie := beginFlow(t, app)
	response := callback(t, app, cookie, "/auth/fake/callback?error=access_denied&error_description=callback-description-secret")
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "Authorization was declined") {
		t.Fatalf("response = %d, %s", response.Code, response.Body.String())
	}
	combined := response.Body.String() + logs.String()
	for _, secret := range []string{"provider-description-secret", "callback-description-secret"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("callback or logs expose %q: %s", secret, combined)
		}
	}
	calls := provider.CompleteCalls()
	if len(calls) != 1 || calls[0].Callback.Error != "access_denied" || calls[0].Callback.ErrorDescription != "callback-description-secret" {
		t.Fatalf("CompleteCalls() = %+v", calls)
	}
	replay := callback(t, app, cookie, "/auth/fake/callback?error=access_denied")
	if replay.Code != http.StatusBadRequest || provider.CompleteCallCount() != 1 {
		t.Fatalf("denial replay response = %d, complete calls = %d", replay.Code, provider.CompleteCallCount())
	}
}

func TestBeginFailureDoesNotCreateCookieOrLogErrorDetails(t *testing.T) {
	var logs bytes.Buffer
	app, provider, store := newTestApplication(t, false, nil)
	app.logger = log.New(&logs, "", 0)
	provider.ConfigureBegin(gociconnect.Authorization{}, errors.New("client-secret-value"))
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/auth/fake", nil))
	if response.Code != http.StatusBadGateway || len(response.Result().Cookies()) != 0 {
		t.Fatalf("response = %d, cookies = %+v", response.Code, response.Result().Cookies())
	}
	store.mu.Lock()
	stored := len(store.sessions)
	store.mu.Unlock()
	if stored != 0 || strings.Contains(logs.String(), "client-secret-value") {
		t.Fatalf("stored sessions = %d, logs = %s", stored, logs.String())
	}
}

func TestManagerFromEnvironmentSupportsOneOrBothProviders(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want []string
	}{
		{
			name: "GitHub only",
			env: map[string]string{
				"GITHUB_CLIENT_ID":     "github-id",
				"GITHUB_CLIENT_SECRET": "github-secret",
				"GITHUB_REDIRECT_URL":  "http://127.0.0.1:8080/auth/github/callback",
			},
			want: []string{"github"},
		},
		{
			name: "Google only",
			env: map[string]string{
				"GOOGLE_CLIENT_ID":     "google-id",
				"GOOGLE_CLIENT_SECRET": "google-secret",
				"GOOGLE_REDIRECT_URL":  "http://127.0.0.1:8080/auth/google/callback",
			},
			want: []string{"google"},
		},
		{
			name: "both",
			env: map[string]string{
				"GITHUB_CLIENT_ID":     "github-id",
				"GITHUB_CLIENT_SECRET": "github-secret",
				"GITHUB_REDIRECT_URL":  "http://127.0.0.1:8080/auth/github/callback",
				"GOOGLE_CLIENT_ID":     "google-id",
				"GOOGLE_CLIENT_SECRET": "google-secret",
				"GOOGLE_REDIRECT_URL":  "http://127.0.0.1:8080/auth/google/callback",
			},
			want: []string{"github", "google"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager, err := managerFromEnvironment(mapEnvironment(test.env))
			if err != nil {
				t.Fatal(err)
			}
			names := manager.Names()
			if len(names) != len(test.want) {
				t.Fatalf("Names() = %v", names)
			}
			for index := range names {
				if names[index] != test.want[index] {
					t.Fatalf("Names() = %v", names)
				}
			}
		})
	}
}

func TestIncompleteEnvironmentIsRejectedWithoutExposingValues(t *testing.T) {
	_, err := managerFromEnvironment(mapEnvironment(map[string]string{
		"GITHUB_CLIENT_ID": "client-id-secret",
	}))
	if err == nil || strings.Contains(err.Error(), "client-id-secret") || !strings.Contains(err.Error(), "GITHUB_CLIENT_SECRET") || !strings.Contains(err.Error(), "GITHUB_REDIRECT_URL") {
		t.Fatalf("managerFromEnvironment() error = %v", err)
	}
}

func newTestApplication(t *testing.T, secure bool, clock *time.Time) (*application, *testkit.Provider, *sessionStore) {
	t.Helper()
	provider := testkit.NewProvider(testkit.ProviderConfig{
		Name: "fake",
		Authorization: gociconnect.Authorization{
			URL: "https://provider.example/authorize?state=provider-state",
			Session: gociconnect.AuthorizationSession{
				State:        "provider-state",
				PKCEVerifier: "provider-verifier",
			},
		},
		CompletedUser: gociconnect.User{
			Provider: "fake",
			ID:       "user-id",
			Nickname: "example-login",
			Name:     "Example User",
			Email:    "user@example.com",
			Token: gociconnect.Token{
				AccessToken:  "browser-access-token",
				RefreshToken: "browser-refresh-token",
			},
		},
	})
	manager := gociconnect.NewManager()
	if err := manager.Register(provider); err != nil {
		t.Fatal(err)
	}
	store := newSessionStore(time.Minute)
	store.random = bytes.NewReader(bytes.Repeat([]byte{0x7a}, sessionIDBytes*8))
	if clock != nil {
		store.now = func() time.Time { return *clock }
	}
	return newApplication(manager, store, secure, log.New(io.Discard, "", 0)), provider, store
}

func beginFlow(t *testing.T, app *application) *http.Cookie {
	t.Helper()
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/auth/fake", nil))
	if response.Code != http.StatusFound {
		t.Fatalf("begin response = %d, %s", response.Code, response.Body.String())
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			return cookie
		}
	}
	t.Fatal("begin response did not set the session cookie")
	return nil
}

func callback(t *testing.T, app *application, cookie *http.Cookie, target string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	return response
}

func mapEnvironment(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestSessionStoreConcurrentConsumptionIsOneTime(t *testing.T) {
	store := newSessionStore(time.Minute)
	store.random = bytes.NewReader(bytes.Repeat([]byte{0x22}, sessionIDBytes))
	id, _, err := store.create("fake", gociconnect.AuthorizationSession{State: "state"})
	if err != nil {
		t.Fatal(err)
	}
	const consumers = 50
	var successes atomic.Int32
	var wait sync.WaitGroup
	for range consumers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := store.consume(id, "fake"); err == nil {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful consumptions = %d", successes.Load())
	}
}
