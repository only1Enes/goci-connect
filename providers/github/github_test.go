package github

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

func TestAuthorizationURL(t *testing.T) {
	provider, err := New(Config{
		ClientID:     "github-client-id",
		ClientSecret: "github-client-secret",
		RedirectURL:  "https://app.example/github/callback",
		Random:       deterministicRandom(4),
	})
	if err != nil {
		t.Fatal(err)
	}
	if provider.Name() != "github" || !provider.Capabilities().PKCE || provider.Capabilities().TokenRefresh {
		t.Fatalf("provider configuration = %q, %+v", provider.Name(), provider.Capabilities())
	}

	authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != authorizationEndpoint {
		t.Fatalf("authorization endpoint = %q", parsed.Scheme+"://"+parsed.Host+parsed.Path)
	}
	if query.Get("client_id") != "github-client-id" || query.Get("redirect_uri") != "https://app.example/github/callback" || query.Get("response_type") != "code" {
		t.Fatalf("authorization query = %v", query)
	}
	if _, exists := query["scope"]; exists {
		t.Fatalf("default authorization unexpectedly requests scopes: %v", query)
	}
	assertAuthorizationSecurity(t, authorization, query)

	custom, err := provider.Begin(context.Background(), gociconnect.BeginRequest{Scopes: []string{"read:user", "user:email"}})
	if err != nil {
		t.Fatal(err)
	}
	customURL, err := url.Parse(custom.URL)
	if err != nil {
		t.Fatal(err)
	}
	if customURL.Query().Get("scope") != "read:user user:email" {
		t.Fatalf("custom scopes = %q", customURL.Query().Get("scope"))
	}
}

func TestConfiguredScopesCanBeOverriddenPerRequest(t *testing.T) {
	provider, err := New(Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://app.example/callback",
		Scopes:       []string{"read:user"},
		Random:       deterministicRandom(4),
	})
	if err != nil {
		t.Fatal(err)
	}
	defaults, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	override, err := provider.Begin(context.Background(), gociconnect.BeginRequest{Scopes: []string{"user:email"}})
	if err != nil {
		t.Fatal(err)
	}
	if authorizationScope(t, defaults.URL) != "read:user" || authorizationScope(t, override.URL) != "user:email" {
		t.Fatalf("scopes = default %q, override %q", authorizationScope(t, defaults.URL), authorizationScope(t, override.URL))
	}
}

func TestUserMappingAndNumericID(t *testing.T) {
	const raw = `{"login":"octocat","id":583231,"avatar_url":"https://avatars.example/octocat","name":"The Octocat","email":"octocat@example.com"}`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/user" {
			http.NotFound(writer, request)
			return
		}
		if request.Header.Get("Authorization") != "Bearer existing-token" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		writeJSON(writer, http.StatusOK, raw)
	}))
	defer server.Close()
	provider := testProvider(t, server)

	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "existing-token"})
	if err != nil {
		t.Fatalf("User() error = %v", err)
	}
	if user.Provider != "github" || user.ID != "583231" || user.Nickname != "octocat" || user.Name != "The Octocat" || user.Email != "octocat@example.com" || user.AvatarURL != "https://avatars.example/octocat" {
		t.Fatalf("User() = %+v", user)
	}
	if user.Token.AccessToken != "existing-token" || string(user.Raw) != raw {
		t.Fatalf("token or raw payload was not preserved: token=%+v raw=%s", user.Token, user.Raw)
	}
}

func TestNullOptionalProfileFields(t *testing.T) {
	var emailRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/user":
			writeJSON(writer, http.StatusOK, `{"login":"octocat","id":42,"name":null,"email":null,"avatar_url":null}`)
		case "/user/emails":
			emailRequests.Add(1)
			writeJSON(writer, http.StatusForbidden, `{"message":"Resource not accessible"}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := testProvider(t, server)

	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token"})
	if err != nil {
		t.Fatalf("User() error = %v", err)
	}
	if user.Name != "" || user.Email != "" || user.AvatarURL != "" || emailRequests.Load() != 1 {
		t.Fatalf("User() = %+v, email requests = %d", user, emailRequests.Load())
	}
}

func TestEmailFallbackPrefersVerifiedPrimary(t *testing.T) {
	server := githubFlowServer(t, `{"access_token":"access-token","token_type":"bearer","scope":"read:user,user:email"}`,
		`{"login":"octocat","id":1,"name":"Octo Cat","email":null}`,
		`[
			{"email":"first@example.com","primary":false,"verified":true},
			{"email":"primary-unverified@example.com","primary":true,"verified":false},
			{"email":"primary@example.com","primary":true,"verified":true}
		]`)
	defer server.Close()
	provider := testProvider(t, server)

	user, err := complete(t, provider)
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if user.Email != "primary@example.com" || len(user.Token.Scopes) != 2 || user.Token.Scopes[1] != "user:email" {
		t.Fatalf("User() = %+v", user)
	}
}

func TestEmailFallbackIsOptional(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		emailBody  string
		wantEmail  string
		wantCalled bool
	}{
		{"first verified when no primary is usable", http.StatusOK, `[{"email":"unverified@example.com","primary":true,"verified":false},{"email":"verified@example.com","verified":true}]`, "verified@example.com", true},
		{"no usable email", http.StatusOK, `[{"email":"","primary":true,"verified":true},{"email":"unverified@example.com","verified":false}]`, "", true},
		{"unauthorized endpoint", http.StatusUnauthorized, `{"message":"Bad credentials"}`, "", true},
		{"malformed response", http.StatusOK, `{not-json`, "", true},
		{"known scope lacks permission", http.StatusOK, `[{"email":"should-not-load@example.com","primary":true,"verified":true}]`, "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var emailRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/token":
					writeJSON(writer, http.StatusOK, `{"access_token":"access-token","token_type":"bearer","scope":"read:user"}`)
				case "/user":
					writeJSON(writer, http.StatusOK, `{"login":"octocat","id":7,"email":null}`)
				case "/user/emails":
					emailRequests.Add(1)
					writeJSON(writer, test.status, test.emailBody)
				default:
					http.NotFound(writer, request)
				}
			}))
			defer server.Close()
			provider := testProvider(t, server)

			var user gociconnect.User
			var err error
			if test.wantCalled {
				user, err = provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token"})
			} else {
				user, err = complete(t, provider)
			}
			if err != nil {
				t.Fatalf("load user error = %v", err)
			}
			if user.Email != test.wantEmail {
				t.Fatalf("email = %q, want %q", user.Email, test.wantEmail)
			}
			wantRequests := int32(0)
			if test.wantCalled {
				wantRequests = 1
			}
			if emailRequests.Load() != wantRequests {
				t.Fatalf("email requests = %d, want %d", emailRequests.Load(), wantRequests)
			}
		})
	}
}

func TestMalformedAndErrorUserResponses(t *testing.T) {
	tests := []struct {
		name string
		code int
		body string
		want error
	}{
		{"malformed JSON", http.StatusOK, `{not-json`, gociconnect.ErrDecoding},
		{"invalid numeric ID", http.StatusOK, `{"id":"not-a-number","login":"octocat"}`, gociconnect.ErrDecoding},
		{"API error", http.StatusUnauthorized, `{"message":"Bad credentials"}`, gociconnect.ErrProviderResponse},
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

func TestCanceledEmailFallbackCancelsUserLoading(t *testing.T) {
	emailStarted := make(chan struct{})
	releaseEmail := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/user":
			writeJSON(writer, http.StatusOK, `{"login":"octocat","id":9,"email":null}`)
		case "/user/emails":
			close(emailStarted)
			<-releaseEmail
			writeJSON(writer, http.StatusOK, `[]`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := testProvider(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := provider.User(ctx, gociconnect.UserRequest{AccessToken: "access-token"})
		done <- err
	}()
	<-emailStarted
	cancel()
	close(releaseEmail)
	err := <-done
	if !errors.Is(err, context.Canceled) || !errors.Is(err, gociconnect.ErrTransport) {
		t.Fatalf("User() error = %v", err)
	}
}

func TestTokenExchangeErrorRedactsProviderContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/token" {
			http.NotFound(writer, request)
			return
		}
		writeJSON(writer, http.StatusUnauthorized, `{"error":"bad_verification_code","error_description":"client-secret access-token authorization-code"}`)
	}))
	defer server.Close()
	provider := testProvider(t, server)
	_, err := complete(t, provider)
	if !errors.Is(err, gociconnect.ErrTokenExchange) {
		t.Fatalf("Complete() error = %v", err)
	}
	formatted := fmt.Sprintf("%v|%+v|%#v", err, err, err)
	for _, secret := range []string{"client-secret", "access-token", "authorization-code", "bad_verification_code"} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("token error exposes %q: %s", secret, formatted)
		}
	}
}

func TestSecretRedaction(t *testing.T) {
	config := Config{
		ClientID:     "visible-client-id-secret",
		ClientSecret: "client-secret-value",
		RedirectURL:  "https://app.example/callback?secret=redirect-secret",
		Scopes:       []string{"scope-secret"},
	}
	provider, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%+v|%#v", config, config, config, provider, provider, provider)
	for _, secret := range []string{"visible-client-id-secret", "client-secret-value", "redirect-secret", "scope-secret"} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("formatted configuration exposes %q: %s", secret, formatted)
		}
	}
}

func validConfig(client *http.Client) Config {
	return Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://app.example/callback",
		HTTPClient:   client,
		Random:       deterministicRandom(16),
	}
}

func testProvider(t *testing.T, server *httptest.Server) *oauth2provider.Provider {
	t.Helper()
	provider, err := newWithEndpoints(validConfig(server.Client()), endpoints{
		authorization: server.URL + "/authorize",
		token:         server.URL + "/token",
		api:           server.URL,
	})
	if err != nil {
		t.Fatalf("newWithEndpoints() error = %v", err)
	}
	return provider
}

func githubFlowServer(t *testing.T, token, user, emails string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			writeJSON(writer, http.StatusOK, token)
		case "/user":
			writeJSON(writer, http.StatusOK, user)
		case "/user/emails":
			writeJSON(writer, http.StatusOK, emails)
		default:
			http.NotFound(writer, request)
		}
	}))
}

func complete(t *testing.T, provider *oauth2provider.Provider) (gociconnect.User, error) {
	t.Helper()
	authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil {
		return gociconnect.User{}, err
	}
	return provider.Complete(context.Background(), gociconnect.CompleteRequest{
		Callback: gociconnect.Callback{Code: "authorization-code", State: authorization.Session.State},
		Session:  authorization.Session,
	})
}

func deterministicRandom(blocks int) io.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0x42}, blocks*64))
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

func authorizationScope(t *testing.T, authorizationURL string) string {
	t.Helper()
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Query().Get("scope")
}

func writeJSON(writer http.ResponseWriter, status int, body string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, body)
}
