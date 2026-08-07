package gitlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	gociconnect "github.com/only1enes/goci-connect"
	"github.com/only1enes/goci-connect/oauth2provider"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing client ID", func(config *Config) { config.ClientID = "" }},
		{"missing client secret", func(config *Config) { config.ClientSecret = "" }},
		{"missing redirect URL", func(config *Config) { config.RedirectURL = "" }},
		{"invalid redirect URL", func(config *Config) { config.RedirectURL = "://invalid" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig(nil)
			test.mutate(&config)
			_, err := New(config)
			if !errors.Is(err, gociconnect.ErrInvalidConfiguration) {
				t.Fatalf("New() error = %v", err)
			}
		})
	}
}

func TestDefaultGitLabEndpointsAndScopes(t *testing.T) {
	target, err := endpointsForBaseURL("")
	if err != nil {
		t.Fatal(err)
	}
	if target.authorization != "https://gitlab.com/oauth/authorize" || target.token != "https://gitlab.com/oauth/token" || target.currentUser != "https://gitlab.com/api/v4/user" {
		t.Fatalf("default endpoints = %+v", target)
	}
	provider, err := New(validConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	if provider.Name() != providerName || !provider.Capabilities().PKCE || !provider.Capabilities().TokenRefresh {
		t.Fatalf("provider = %q, capabilities = %+v", provider.Name(), provider.Capabilities())
	}
	authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseAuthorizationURL(t, authorization.URL)
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != target.authorization || parsed.Query().Get("scope") != "read_user" {
		t.Fatalf("authorization URL = %q", authorization.URL)
	}
	assertAuthorizationSecurity(t, authorization, parsed.Query())
}

func TestSelfManagedBaseURLAndTrailingSlashes(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		wantBase string
	}{
		{"root installation", "https://gitlab.example.com", "https://gitlab.example.com"},
		{"root trailing slash", "https://gitlab.example.com/", "https://gitlab.example.com"},
		{"relative URL root", "https://code.example.com/gitlab", "https://code.example.com/gitlab"},
		{"relative URL trailing slashes", "https://code.example.com/platform/gitlab///", "https://code.example.com/platform/gitlab"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := endpointsForBaseURL(test.baseURL)
			if err != nil {
				t.Fatal(err)
			}
			if target.authorization != test.wantBase+"/oauth/authorize" || target.token != test.wantBase+"/oauth/token" || target.currentUser != test.wantBase+"/api/v4/user" {
				t.Fatalf("endpoints = %+v", target)
			}
			config := validConfig(nil)
			config.BaseURL = test.baseURL
			provider, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
			if err != nil {
				t.Fatal(err)
			}
			if got := parseAuthorizationURL(t, authorization.URL); got.Scheme+"://"+got.Host+got.Path != target.authorization {
				t.Fatalf("authorization URL = %q", authorization.URL)
			}
		})
	}
}

func TestInvalidAndUnsupportedBaseURLs(t *testing.T) {
	values := []string{
		"gitlab.example.com",
		"https:///missing-host",
		"https://user:password@gitlab.example.com",
		"https://gitlab.example.com?tenant=secret",
		"https://gitlab.example.com#fragment",
		"https://gitlab.example.com/root/../admin",
		"https://gitlab.example.com/root/%2e%2e/admin",
		"https://gitlab.example.com/root%2Fadmin",
		"http://gitlab.example.com",
		"ftp://gitlab.example.com",
		"file:///srv/gitlab",
		"javascript:alert(1)",
	}
	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			config := validConfig(nil)
			config.BaseURL = value
			_, err := New(config)
			if !errors.Is(err, gociconnect.ErrInvalidConfiguration) {
				t.Fatalf("New() error = %v", err)
			}
		})
	}
}

func TestUserFromTokenMapping(t *testing.T) {
	const raw = `{"id":42,"username":"ada","name":"Ada Lovelace","email":"ada@example.com","public_email":"public@example.com","avatar_url":"https://gitlab.example.com/uploads/avatar.png"}`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v4/user" {
			http.NotFound(writer, request)
			return
		}
		if request.Header.Get("Authorization") != "Bearer existing-access-token" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		writeJSON(writer, http.StatusOK, raw)
	}))
	defer server.Close()
	provider := testProvider(t, server)

	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "existing-access-token"})
	if err != nil {
		t.Fatalf("User() error = %v", err)
	}
	if user.Provider != providerName || user.ID != "42" || user.Nickname != "ada" || user.Name != "Ada Lovelace" || user.Email != "ada@example.com" || user.AvatarURL != "https://gitlab.example.com/uploads/avatar.png" {
		t.Fatalf("User() = %+v", user)
	}
	if user.Token.AccessToken != "existing-access-token" || string(user.Raw) != raw {
		t.Fatalf("token or raw payload mismatch: token=%+v raw=%s", user.Token, user.Raw)
	}
}

func TestMissingOptionalProfileFields(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		wantEmail string
	}{
		{"all optional fields missing", `{"id":7}`, ""},
		{"nullable optional fields", `{"id":7,"username":null,"name":null,"email":null,"public_email":null,"avatar_url":null}`, ""},
		{"public email fallback", `{"id":7,"email":null,"public_email":"public@example.com"}`, "public@example.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := userServer(test.payload)
			defer server.Close()
			provider := testProvider(t, server)
			user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token"})
			if err != nil {
				t.Fatal(err)
			}
			if user.ID != "7" || user.Email != test.wantEmail {
				t.Fatalf("User() = %+v", user)
			}
		})
	}
}

func TestMalformedResponsesAndAPIErrors(t *testing.T) {
	tests := []struct {
		name string
		code int
		body string
		want error
	}{
		{"malformed JSON", http.StatusOK, `{not-json`, gociconnect.ErrDecoding},
		{"missing ID", http.StatusOK, `{"username":"ada"}`, gociconnect.ErrDecoding},
		{"invalid ID", http.StatusOK, `{"id":"not-an-integer"}`, gociconnect.ErrDecoding},
		{"GitLab API error", http.StatusUnauthorized, `{"message":"401 Unauthorized"}`, gociconnect.ErrProviderResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writeJSON(writer, test.code, test.body)
			}))
			defer server.Close()
			provider := testProvider(t, server)
			_, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token"})
			if !errors.Is(err, test.want) {
				t.Fatalf("User() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestStateAndPKCEIntegration(t *testing.T) {
	var tokenRequests atomic.Int32
	var exchangedVerifier string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth/token":
			tokenRequests.Add(1)
			if err := request.ParseForm(); err != nil {
				t.Error(err)
			}
			exchangedVerifier = request.Form.Get("code_verifier")
			if request.Form.Get("client_id") != "client-id" || request.Form.Get("client_secret") != "client-secret" || request.Form.Get("code") != "authorization-code" {
				t.Errorf("token form = %v", request.Form)
			}
			writeJSON(writer, http.StatusOK, `{"access_token":"access-token","refresh_token":"refresh-token","token_type":"Bearer","scope":"read_user"}`)
		case "/api/v4/user":
			writeJSON(writer, http.StatusOK, `{"id":91,"username":"grace","name":"Grace Hopper"}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := testProvider(t, server)

	authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	assertAuthorizationSecurity(t, authorization, parseAuthorizationURL(t, authorization.URL).Query())
	_, err = provider.Complete(context.Background(), gociconnect.CompleteRequest{
		Callback: gociconnect.Callback{Code: "authorization-code", State: "wrong-state"},
		Session:  authorization.Session,
	})
	if !errors.Is(err, gociconnect.ErrStateValidation) || tokenRequests.Load() != 0 {
		t.Fatalf("state mismatch error = %v, token requests = %d", err, tokenRequests.Load())
	}

	user, err := provider.Complete(context.Background(), gociconnect.CompleteRequest{
		Callback: gociconnect.Callback{Code: "authorization-code", State: authorization.Session.State},
		Session:  authorization.Session,
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if exchangedVerifier != authorization.Session.PKCEVerifier || user.ID != "91" || user.Token.RefreshToken != "refresh-token" {
		t.Fatalf("verifier = %q, user = %+v", exchangedVerifier, user)
	}
}

func TestConcurrentProvidersUseIndependentGitLabHosts(t *testing.T) {
	var hostOneRequests atomic.Int32
	var hostTwoRequests atomic.Int32
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body string
		switch request.URL.Host {
		case "one.gitlab.example":
			hostOneRequests.Add(1)
			if request.URL.Path != "/gitlab/api/v4/user" {
				return nil, fmt.Errorf("host one path = %q", request.URL.Path)
			}
			body = `{"id":101,"username":"one"}`
		case "two.gitlab.example":
			hostTwoRequests.Add(1)
			if request.URL.Path != "/platform/gitlab/api/v4/user" {
				return nil, fmt.Errorf("host two path = %q", request.URL.Path)
			}
			body = `{"id":202,"username":"two"}`
		default:
			return nil, fmt.Errorf("unexpected host %q", request.URL.Host)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	})
	client := &http.Client{Transport: transport}
	firstConfig := validConfig(client)
	firstConfig.BaseURL = "https://one.gitlab.example/gitlab"
	first, err := New(firstConfig)
	if err != nil {
		t.Fatal(err)
	}
	secondConfig := validConfig(client)
	secondConfig.BaseURL = "https://two.gitlab.example/platform/gitlab/"
	second, err := New(secondConfig)
	if err != nil {
		t.Fatal(err)
	}

	const calls = 100
	errorsChannel := make(chan error, calls*2)
	var wait sync.WaitGroup
	for range calls {
		wait.Add(2)
		go loadAndCheckUser(&wait, errorsChannel, first, "101")
		go loadAndCheckUser(&wait, errorsChannel, second, "202")
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
	if hostOneRequests.Load() != calls || hostTwoRequests.Load() != calls {
		t.Fatalf("requests = host one %d, host two %d", hostOneRequests.Load(), hostTwoRequests.Load())
	}
	firstAuthorization, err := first.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	secondAuthorization, err := second.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if parseAuthorizationURL(t, firstAuthorization.URL).Host != "one.gitlab.example" || parseAuthorizationURL(t, secondAuthorization.URL).Host != "two.gitlab.example" {
		t.Fatal("authorization hosts crossed provider instances")
	}
}

func loadAndCheckUser(wait *sync.WaitGroup, errorsChannel chan<- error, provider *oauth2provider.Provider, wantID string) {
	defer wait.Done()
	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token"})
	if err != nil {
		errorsChannel <- err
		return
	}
	if user.ID != wantID {
		errorsChannel <- fmt.Errorf("user ID = %q, want %q", user.ID, wantID)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func validConfig(client *http.Client) Config {
	return Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://app.example/callback",
		HTTPClient:   client,
		Random:       deterministicRandom(500),
	}
}

func testProvider(t *testing.T, server *httptest.Server) *oauth2provider.Provider {
	t.Helper()
	provider, err := newWithEndpoints(validConfig(server.Client()), endpoints{
		authorization: server.URL + "/oauth/authorize",
		token:         server.URL + "/oauth/token",
		currentUser:   server.URL + "/api/v4/user",
	})
	if err != nil {
		t.Fatalf("newWithEndpoints() error = %v", err)
	}
	return provider
}

func userServer(payload string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, payload)
	}))
}

func deterministicRandom(blocks int) io.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0x51}, blocks*64))
}

func parseAuthorizationURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func assertAuthorizationSecurity(t *testing.T, authorization gociconnect.Authorization, query url.Values) {
	t.Helper()
	if authorization.Session.State == "" || query.Get("state") != authorization.Session.State || authorization.Session.PKCEVerifier == "" {
		t.Fatalf("authorization session = %+v, query = %v", authorization.Session, query)
	}
	digest := sha256.Sum256([]byte(authorization.Session.PKCEVerifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") != wantChallenge {
		t.Fatalf("PKCE query = %v", query)
	}
}

func writeJSON(writer http.ResponseWriter, status int, body string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, body)
}
