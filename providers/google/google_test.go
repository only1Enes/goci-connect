package google

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
		{"protected configured parameter", func(config *Config) {
			config.AuthorizationParameters = url.Values{"state": {"unsafe"}}
		}},
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

func TestAuthorizationURLAndScopes(t *testing.T) {
	parameters := url.Values{
		"access_type":            {"offline"},
		"include_granted_scopes": {"true"},
	}
	provider, err := New(Config{
		ClientID:                "google-client-id",
		ClientSecret:            "google-client-secret",
		RedirectURL:             "https://app.example/google/callback",
		AuthorizationParameters: parameters,
		Random:                  deterministicRandom(8),
	})
	if err != nil {
		t.Fatal(err)
	}
	parameters.Set("access_type", "mutated")
	if provider.Name() != providerName || !provider.Capabilities().PKCE || !provider.Capabilities().TokenRefresh {
		t.Fatalf("provider = %q, capabilities = %+v", provider.Name(), provider.Capabilities())
	}

	authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{Parameters: url.Values{
		"prompt":     {"consent"},
		"login_hint": {"person@example.com"},
		"hd":         {"example.com"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != authorizationEndpoint {
		t.Fatalf("authorization endpoint = %q", parsed.Scheme+"://"+parsed.Host+parsed.Path)
	}
	query := parsed.Query()
	if query.Get("client_id") != "google-client-id" || query.Get("redirect_uri") != "https://app.example/google/callback" || query.Get("response_type") != "code" {
		t.Fatalf("authorization query = %v", query)
	}
	if query.Get("scope") != "openid profile email" {
		t.Fatalf("default scopes = %q", query.Get("scope"))
	}
	if query.Get("access_type") != "offline" || query.Get("include_granted_scopes") != "true" || query.Get("prompt") != "consent" || query.Get("login_hint") != "person@example.com" || query.Get("hd") != "example.com" {
		t.Fatalf("Google authorization parameters = %v", query)
	}
	assertAuthorizationSecurity(t, authorization, query)

	_, err = provider.Begin(context.Background(), gociconnect.BeginRequest{Parameters: url.Values{"client_id": {"override"}}})
	if !errors.Is(err, gociconnect.ErrInvalidRequest) {
		t.Fatalf("protected request parameter error = %v", err)
	}
}

func TestConfiguredScopesAndRequestOverride(t *testing.T) {
	provider, err := New(Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://app.example/callback",
		Scopes:       []string{"openid", "email"},
		Random:       deterministicRandom(8),
	})
	if err != nil {
		t.Fatal(err)
	}
	configured, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	overridden, err := provider.Begin(context.Background(), gociconnect.BeginRequest{Scopes: []string{"openid", "profile"}})
	if err != nil {
		t.Fatal(err)
	}
	if authorizationScope(t, configured.URL) != "openid email" || authorizationScope(t, overridden.URL) != "openid profile" {
		t.Fatalf("scopes = configured %q, overridden %q", authorizationScope(t, configured.URL), authorizationScope(t, overridden.URL))
	}
}

func TestUserInfoMappingAndUserFromToken(t *testing.T) {
	const raw = `{"sub":"110169484474386276334","name":"Example Person","email":"person@example.com","email_verified":true,"picture":"https://images.example/person.jpg"}`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/userinfo" {
			http.NotFound(writer, request)
			return
		}
		if request.Header.Get("Authorization") != "Bearer existing-access-token" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		writeJSON(writer, http.StatusOK, raw)
	}))
	defer server.Close()
	provider := testProvider(t, server, nil)

	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "existing-access-token"})
	if err != nil {
		t.Fatalf("User() error = %v", err)
	}
	if user.Provider != providerName || user.ID != "110169484474386276334" || user.Nickname != "" || user.Name != "Example Person" || user.Email != "person@example.com" || user.AvatarURL != "https://images.example/person.jpg" {
		t.Fatalf("User() = %+v", user)
	}
	if user.Token.AccessToken != "existing-access-token" || string(user.Raw) != raw {
		t.Fatalf("token or raw UserInfo was not preserved: token=%+v raw=%s", user.Token, user.Raw)
	}
}

func TestMissingOptionalUserInfoFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, `{"sub":"subject-only","name":null,"email":null,"picture":null}`)
	}))
	defer server.Close()
	provider := testProvider(t, server, nil)

	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token"})
	if err != nil {
		t.Fatalf("User() error = %v", err)
	}
	if user.ID != "subject-only" || user.Name != "" || user.Email != "" || user.AvatarURL != "" || user.Nickname != "" {
		t.Fatalf("User() = %+v", user)
	}
}

func TestUnverifiedEmailRemainsProviderSpecificRawData(t *testing.T) {
	const raw = `{"sub":"subject","email":"unverified@example.com","email_verified":false}`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, raw)
	}))
	defer server.Close()
	provider := testProvider(t, server, nil)

	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token"})
	if err != nil {
		t.Fatalf("User() error = %v", err)
	}
	var preserved struct {
		EmailVerified *bool `json:"email_verified"`
	}
	if err := json.Unmarshal(user.Raw, &preserved); err != nil {
		t.Fatal(err)
	}
	if user.Email != "unverified@example.com" || preserved.EmailVerified == nil || *preserved.EmailVerified {
		t.Fatalf("User() = %+v, raw email_verified = %v", user, preserved.EmailVerified)
	}
	if strings.Contains(fmt.Sprintf("%v", user), "unverified@example.com") {
		t.Fatal("formatted user exposes provider-specific raw data")
	}
}

func TestMalformedAndErrorUserInfoResponses(t *testing.T) {
	tests := []struct {
		name string
		code int
		body string
		want error
	}{
		{"malformed JSON", http.StatusOK, `{not-json`, gociconnect.ErrDecoding},
		{"missing required subject", http.StatusOK, `{"name":"No Subject"}`, gociconnect.ErrDecoding},
		{"invalid email verification type", http.StatusOK, `{"sub":"subject","email_verified":"true"}`, gociconnect.ErrDecoding},
		{"API error", http.StatusUnauthorized, `{"error":{"code":401,"message":"Invalid Credentials"}}`, gociconnect.ErrProviderResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writeJSON(writer, test.code, test.body)
			}))
			defer server.Close()
			provider := testProvider(t, server, nil)

			_, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token"})
			if !errors.Is(err, test.want) {
				t.Fatalf("User() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestStateAndPKCEIntegrationUsesUserInfo(t *testing.T) {
	var tokenRequests atomic.Int32
	var exchangedVerifier string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			tokenRequests.Add(1)
			if err := request.ParseForm(); err != nil {
				t.Error(err)
			}
			exchangedVerifier = request.Form.Get("code_verifier")
			if request.Form.Get("code") != "authorization-code" || request.Form.Get("client_secret") != "client-secret" {
				t.Errorf("token form = %v", request.Form)
			}
			writeJSON(writer, http.StatusOK, `{"access_token":"access-token","token_type":"Bearer","scope":"openid profile email","id_token":"unverified.header.payload"}`)
		case "/userinfo":
			writeJSON(writer, http.StatusOK, `{"sub":"trusted-userinfo-subject","name":"Trusted UserInfo Name","email_verified":true}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := testProvider(t, server, nil)

	authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatal(err)
	}
	assertAuthorizationSecurity(t, authorization, parsed.Query())

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
	if exchangedVerifier != authorization.Session.PKCEVerifier {
		t.Fatalf("exchanged verifier = %q", exchangedVerifier)
	}
	if user.ID != "trusted-userinfo-subject" || user.Name != "Trusted UserInfo Name" || string(user.Raw) != `{"sub":"trusted-userinfo-subject","name":"Trusted UserInfo Name","email_verified":true}` {
		t.Fatalf("Complete() user = %+v", user)
	}
	if _, exists := user.Token.Metadata["id_token"]; exists || strings.Contains(fmt.Sprintf("%v", user.Token), "unverified.header.payload") {
		t.Fatal("unverified ID token was retained as trusted identity data")
	}
}

func TestSecretRedaction(t *testing.T) {
	config := Config{
		ClientID:     "google-client-id-secret",
		ClientSecret: "google-client-secret",
		RedirectURL:  "https://app.example/callback?value=redirect-secret",
		Scopes:       []string{"scope-secret"},
		AuthorizationParameters: url.Values{
			"login_hint": {"person-secret@example.com"},
		},
	}
	provider, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%+v|%#v", config, config, config, provider, provider, provider)
	for _, secret := range []string{"google-client-id-secret", "google-client-secret", "redirect-secret", "scope-secret", "person-secret@example.com"} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("formatted provider exposes %q: %s", secret, formatted)
		}
	}
}

func validConfig(client *http.Client) Config {
	return Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://app.example/callback",
		HTTPClient:   client,
		Random:       deterministicRandom(32),
	}
}

func testProvider(t *testing.T, server *httptest.Server, configure func(*Config)) *oauth2provider.Provider {
	t.Helper()
	config := validConfig(server.Client())
	if configure != nil {
		configure(&config)
	}
	provider, err := newWithEndpoints(config, endpoints{
		authorization: server.URL + "/authorize",
		token:         server.URL + "/token",
		userInfo:      server.URL + "/userinfo",
	})
	if err != nil {
		t.Fatalf("newWithEndpoints() error = %v", err)
	}
	return provider
}

func deterministicRandom(blocks int) io.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0x37}, blocks*64))
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
