package discord

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

func TestAuthorizationURLAndScopes(t *testing.T) {
	provider, err := New(Config{
		ClientID:     "discord-client-id",
		ClientSecret: "discord-client-secret",
		RedirectURL:  "https://app.example/discord/callback",
		Random:       deterministicRandom(8),
	})
	if err != nil {
		t.Fatal(err)
	}
	if provider.Name() != providerName || !provider.Capabilities().PKCE || !provider.Capabilities().TokenRefresh {
		t.Fatalf("provider = %q, capabilities = %+v", provider.Name(), provider.Capabilities())
	}

	authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{Parameters: url.Values{"prompt": {"consent"}}})
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
	if query.Get("client_id") != "discord-client-id" || query.Get("redirect_uri") != "https://app.example/discord/callback" || query.Get("response_type") != "code" {
		t.Fatalf("authorization query = %v", query)
	}
	if query.Get("scope") != "identify email" || query.Get("prompt") != "consent" {
		t.Fatalf("scopes or parameters = %v", query)
	}
	assertAuthorizationSecurity(t, authorization, query)

	custom, err := provider.Begin(context.Background(), gociconnect.BeginRequest{Scopes: []string{"identify"}})
	if err != nil {
		t.Fatal(err)
	}
	if authorizationScope(t, custom.URL) != "identify" {
		t.Fatalf("custom scope = %q", authorizationScope(t, custom.URL))
	}
}

func TestUserFromTokenMapsCurrentUserAndCustomAvatar(t *testing.T) {
	const raw = `{"id":"80351110224678912","username":"nelly","global_name":"Nelly Display","discriminator":"0","avatar":"a_8342729096ea3675442027381ff50dfe","verified":true,"email":"nelly@example.com"}`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/users/@me" {
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
	if user.Provider != providerName || user.ID != "80351110224678912" || user.Nickname != "nelly" || user.Name != "Nelly Display" || user.Email != "nelly@example.com" {
		t.Fatalf("User() = %+v", user)
	}
	wantAvatar := "https://cdn.discordapp.com/avatars/80351110224678912/a_8342729096ea3675442027381ff50dfe.png"
	if user.AvatarURL != wantAvatar || user.Token.AccessToken != "existing-access-token" || string(user.Raw) != raw {
		t.Fatalf("avatar, token, or raw payload mismatch: user=%+v raw=%s", user, user.Raw)
	}
}

func TestDisplayNameFallsBackToUsername(t *testing.T) {
	server := userServer(`{"id":"80351110224678912","username":"current_username","global_name":null,"discriminator":"0","avatar":"hash"}`)
	defer server.Close()
	provider := testProvider(t, server)

	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token"})
	if err != nil {
		t.Fatal(err)
	}
	if user.Nickname != "current_username" || user.Name != "current_username" {
		t.Fatalf("User() = %+v", user)
	}
}

func TestMissingAvatarUsesDocumentedDefault(t *testing.T) {
	tests := []struct {
		name          string
		payload       string
		wantAvatarURL string
	}{
		{
			name:          "new username system",
			payload:       `{"id":"80351110224678912","username":"nelly","global_name":"Nelly","discriminator":"0","avatar":null}`,
			wantAvatarURL: "https://cdn.discordapp.com/embed/avatars/5.png",
		},
		{
			name:          "legacy username system",
			payload:       `{"id":"80351110224678912","username":"nelly","global_name":"Nelly","discriminator":"1337","avatar":null}`,
			wantAvatarURL: "https://cdn.discordapp.com/embed/avatars/2.png",
		},
		{
			name:          "missing discriminator",
			payload:       `{"id":"80351110224678912","username":"nelly","avatar":null}`,
			wantAvatarURL: "",
		},
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
			if user.AvatarURL != test.wantAvatarURL {
				t.Fatalf("AvatarURL = %q, want %q", user.AvatarURL, test.wantAvatarURL)
			}
		})
	}
}

func TestMissingEmailIsOptional(t *testing.T) {
	server := userServer(`{"id":"80351110224678912","username":"nelly","global_name":null,"discriminator":"0","avatar":null,"email":null}`)
	defer server.Close()
	provider := testProvider(t, server)

	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token"})
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "" || user.Name != "nelly" {
		t.Fatalf("User() = %+v", user)
	}
}

func TestMalformedPayloadsAndAPIErrors(t *testing.T) {
	tests := []struct {
		name string
		code int
		body string
		want error
	}{
		{"malformed JSON", http.StatusOK, `{not-json`, gociconnect.ErrDecoding},
		{"missing user ID", http.StatusOK, `{"username":"nelly"}`, gociconnect.ErrDecoding},
		{"invalid user ID", http.StatusOK, `{"id":"not-a-snowflake","username":"nelly"}`, gociconnect.ErrDecoding},
		{"wrong user ID type", http.StatusOK, `{"id":80351110224678912,"username":"nelly"}`, gociconnect.ErrDecoding},
		{"Discord API error", http.StatusUnauthorized, `{"message":"401: Unauthorized","code":0}`, gociconnect.ErrProviderResponse},
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
		case "/oauth2/token":
			tokenRequests.Add(1)
			clientID, clientSecret, ok := request.BasicAuth()
			if !ok || clientID != "client-id" || clientSecret != "client-secret" {
				t.Errorf("token authentication = %q, %q, %t", clientID, clientSecret, ok)
			}
			if err := request.ParseForm(); err != nil {
				t.Error(err)
			}
			exchangedVerifier = request.Form.Get("code_verifier")
			if request.Form.Get("code") != "authorization-code" || request.Form.Get("grant_type") != "authorization_code" {
				t.Errorf("token form = %v", request.Form)
			}
			writeJSON(writer, http.StatusOK, `{"access_token":"access-token","refresh_token":"refresh-token","token_type":"Bearer","scope":"identify email"}`)
		case "/users/@me":
			writeJSON(writer, http.StatusOK, `{"id":"80351110224678912","username":"nelly","global_name":"Nelly","discriminator":"0","avatar":null}`)
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
	if exchangedVerifier != authorization.Session.PKCEVerifier || user.ID != "80351110224678912" {
		t.Fatalf("verifier = %q, user = %+v", exchangedVerifier, user)
	}
	if user.Token.RefreshToken != "refresh-token" || len(user.Token.Scopes) != 2 {
		t.Fatalf("token = %+v", user.Token)
	}
}

func TestSecretRedaction(t *testing.T) {
	config := Config{
		ClientID:     "discord-client-id-secret",
		ClientSecret: "discord-client-secret",
		RedirectURL:  "https://app.example/callback?value=redirect-secret",
		Scopes:       []string{"scope-secret"},
	}
	provider, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%+v|%#v", config, config, config, provider, provider, provider)
	for _, secret := range []string{"discord-client-id-secret", "discord-client-secret", "redirect-secret", "scope-secret"} {
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

func testProvider(t *testing.T, server *httptest.Server) *oauth2provider.Provider {
	t.Helper()
	provider, err := newWithEndpoints(validConfig(server.Client()), endpoints{
		authorization: server.URL + "/oauth2/authorize",
		token:         server.URL + "/oauth2/token",
		currentUser:   server.URL + "/users/@me",
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
	return bytes.NewReader(bytes.Repeat([]byte{0x29}, blocks*64))
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
