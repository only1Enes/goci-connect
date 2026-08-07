package oauth2provider_test

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
	"sync"
	"testing"
	"time"

	gociconnect "github.com/only1enes/goci-connect"
	"github.com/only1enes/goci-connect/oauth2provider"
	"golang.org/x/oauth2"
)

type providerUser struct {
	ID     string `json:"id"`
	Login  string `json:"login"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Avatar string `json:"avatar"`
}

func testMapper(raw json.RawMessage) (gociconnect.User, error) {
	var source providerUser
	if err := json.Unmarshal(raw, &source); err != nil {
		return gociconnect.User{}, err
	}
	return gociconnect.User{
		ID:        source.ID,
		Nickname:  source.Login,
		Name:      source.Name,
		Email:     source.Email,
		AvatarURL: source.Avatar,
	}, nil
}

func deterministicRandom(blocks int) *bytes.Reader {
	data := make([]byte, blocks*32)
	for block := range blocks {
		for index := range 32 {
			data[block*32+index] = byte(block%251 + 1)
		}
	}
	return bytes.NewReader(data)
}

func newTestProvider(t *testing.T, providerURL string, options ...func(*oauth2provider.Config)) *oauth2provider.Provider {
	t.Helper()
	config := oauth2provider.Config{
		Name:         "example",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://app.example/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:   providerURL + "/authorize",
			TokenURL:  providerURL + "/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		DefaultScopes: []string{"profile", "email"},
		Capabilities: oauth2provider.Capabilities{
			PKCE:         true,
			TokenRefresh: true,
		},
		Random:       deterministicRandom(400),
		Now:          func() time.Time { return time.Date(2026, time.August, 5, 12, 0, 0, 0, time.UTC) },
		UserEndpoint: providerURL + "/user",
		UserMapper:   oauth2provider.UserMapperFunc(testMapper),
	}
	for _, option := range options {
		option(&config)
	}
	provider, err := oauth2provider.New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return provider
}

func TestAuthorizationURLGeneration(t *testing.T) {
	defaultScopes := []string{"profile", "email"}
	defaultParameters := url.Values{
		"prompt":   {"login"},
		"resource": {"one", "two"},
	}
	provider := newTestProvider(t, "https://provider.example", func(config *oauth2provider.Config) {
		config.DefaultScopes = defaultScopes
		config.AuthorizationParameters = defaultParameters
	})
	defaultScopes[0] = "mutated"
	defaultParameters.Set("prompt", "mutated")

	authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	query := parseAuthorizationQuery(t, authorization.URL)
	if query.Get("client_id") != "client-id" || query.Get("redirect_uri") != "https://app.example/callback" || query.Get("response_type") != "code" {
		t.Fatalf("protocol query = %v", query)
	}
	if query.Get("scope") != "profile email" {
		t.Fatalf("default scope = %q", query.Get("scope"))
	}
	if query.Get("prompt") != "login" || !slicesEqual(query["resource"], []string{"one", "two"}) {
		t.Fatalf("provider parameters = %v", query)
	}
	if authorization.Session.State == "" || query.Get("state") != authorization.Session.State {
		t.Fatalf("state query = %q, session = %q", query.Get("state"), authorization.Session.State)
	}
	if authorization.Session.CreatedAt != time.Date(2026, time.August, 5, 12, 0, 0, 0, time.UTC) {
		t.Fatalf("CreatedAt = %v", authorization.Session.CreatedAt)
	}
	assertPKCEChallenge(t, query, authorization.Session.PKCEVerifier)
}

func TestCustomScopesAndParametersDoNotMutateConfiguration(t *testing.T) {
	provider := newTestProvider(t, "https://provider.example", func(config *oauth2provider.Config) {
		config.AuthorizationParameters = url.Values{"prompt": {"login"}, "resource": {"default"}}
	})
	request := gociconnect.BeginRequest{
		Scopes: []string{"custom", "scope"},
		Parameters: url.Values{
			"prompt": {"consent"},
		},
	}
	authorization, err := provider.Begin(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Scopes[0] = "mutated"
	request.Parameters.Set("prompt", "mutated")
	query := parseAuthorizationQuery(t, authorization.URL)
	if query.Get("scope") != "custom scope" || !slicesEqual(query["prompt"], []string{"consent"}) || query.Get("resource") != "default" {
		t.Fatalf("custom query = %v", query)
	}

	second, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	secondQuery := parseAuthorizationQuery(t, second.URL)
	if secondQuery.Get("scope") != "profile email" || secondQuery.Get("prompt") != "login" {
		t.Fatalf("provider configuration was mutated: %v", secondQuery)
	}
}

func TestProtectedAuthorizationParametersAreRejected(t *testing.T) {
	provider := newTestProvider(t, "https://provider.example")
	for _, key := range []string{"client_id", "Client_Secret", "redirect_uri", "response_type", "scope", "state", "code_challenge", "CODE_CHALLENGE_METHOD", "code_verifier"} {
		t.Run(key, func(t *testing.T) {
			_, err := provider.Begin(context.Background(), gociconnect.BeginRequest{Parameters: url.Values{key: {"unsafe"}}})
			if !errors.Is(err, gociconnect.ErrInvalidRequest) {
				t.Fatalf("Begin() error = %v", err)
			}
		})
	}
}

func TestProtectedConfigurationParametersAreRejected(t *testing.T) {
	tests := []func(*oauth2provider.Config){
		func(config *oauth2provider.Config) { config.AuthorizationParameters = url.Values{"state": {"unsafe"}} },
		func(config *oauth2provider.Config) { config.Endpoint.AuthURL += "?CLIENT_ID=unsafe" },
	}
	for index, option := range tests {
		t.Run(fmt.Sprintf("case-%d", index), func(t *testing.T) {
			config := validConfig("https://provider.example")
			option(&config)
			_, err := oauth2provider.New(config)
			if !errors.Is(err, gociconnect.ErrInvalidConfiguration) {
				t.Fatalf("New() error = %v", err)
			}
		})
	}
}

func TestStateMismatchStopsExchange(t *testing.T) {
	var tokenRequests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		tokenRequests++
		http.Error(writer, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	provider := newTestProvider(t, server.URL)

	_, err := provider.Complete(context.Background(), gociconnect.CompleteRequest{
		Callback: gociconnect.Callback{Code: "authorization-code", State: "wrong-state"},
		Session:  gociconnect.AuthorizationSession{State: "expected-state", PKCEVerifier: "verifier"},
	})
	if !errors.Is(err, gociconnect.ErrStateValidation) {
		t.Fatalf("Complete() error = %v", err)
	}
	if tokenRequests != 0 {
		t.Fatalf("token requests = %d", tokenRequests)
	}
}

func TestStateDisabledFlowRetainsPKCE(t *testing.T) {
	var verifier string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			_ = request.ParseForm()
			verifier = request.Form.Get("code_verifier")
			writeJSON(writer, `{"access_token":"access-token","token_type":"Bearer"}`)
		case "/user":
			writeJSON(writer, `{"id":"user-1"}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newTestProvider(t, server.URL)
	authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{DisableState: true})
	if err != nil {
		t.Fatal(err)
	}
	query := parseAuthorizationQuery(t, authorization.URL)
	if _, exists := query["state"]; exists || authorization.Session.State != "" || !authorization.Session.StateVerificationDisabled {
		t.Fatalf("state-disabled authorization = %+v, %v", authorization.Session, query)
	}
	assertPKCEChallenge(t, query, authorization.Session.PKCEVerifier)

	_, err = provider.Complete(context.Background(), gociconnect.CompleteRequest{
		Callback: gociconnect.Callback{Code: "authorization-code"},
		Session:  authorization.Session,
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if verifier != authorization.Session.PKCEVerifier {
		t.Fatalf("exchange verifier = %q", verifier)
	}
}

func TestCallbackDenialAndMissingCodeStopExchange(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(writer, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	provider := newTestProvider(t, server.URL)

	denial := gociconnect.CompleteRequest{Callback: gociconnect.Callback{
		Error:            "access_denied",
		ErrorDescription: "description-access-token-secret",
		ErrorURI:         "https://provider.example/error?secret=refresh-token-secret",
	}}
	_, err := provider.Complete(context.Background(), denial)
	if !errors.Is(err, gociconnect.ErrAuthorizationDenied) {
		t.Fatalf("denial error = %v", err)
	}
	formatted := fmt.Sprintf("%v|%+v|%#v", err, err, err)
	if strings.Contains(formatted, "access-token-secret") || strings.Contains(formatted, "refresh-token-secret") {
		t.Fatalf("denial error exposes callback content: %s", formatted)
	}

	_, err = provider.Complete(context.Background(), gociconnect.CompleteRequest{})
	if !errors.Is(err, gociconnect.ErrInvalidRequest) {
		t.Fatalf("missing-code error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("provider requests = %d", requests)
	}
}

func TestSuccessfulExchangeAndUserLoading(t *testing.T) {
	var exchangedVerifier string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			if err := request.ParseForm(); err != nil {
				t.Error(err)
			}
			if request.Form.Get("grant_type") != "authorization_code" || request.Form.Get("code") != "authorization-code" || request.Form.Get("client_id") != "client-id" || request.Form.Get("client_secret") != "client-secret" {
				t.Errorf("token form = %v", request.Form)
			}
			exchangedVerifier = request.Form.Get("code_verifier")
			writeJSON(writer, `{"access_token":"access-token","refresh_token":"refresh-token","token_type":"Bearer","expires_in":3600,"scope":"profile email"}`)
		case "/user":
			if request.Header.Get("Authorization") != "Bearer access-token" {
				t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
			}
			writeJSON(writer, `{"id":"user-1","login":"octocat","name":"Example User","email":"user@example.com","avatar":"https://example.com/avatar.png"}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newTestProvider(t, server.URL)
	authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	user, err := provider.Complete(context.Background(), gociconnect.CompleteRequest{
		Callback: gociconnect.Callback{Code: "authorization-code", State: authorization.Session.State},
		Session:  authorization.Session,
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if exchangedVerifier != authorization.Session.PKCEVerifier {
		t.Fatalf("exchange verifier = %q", exchangedVerifier)
	}
	if user.Provider != "example" || user.ID != "user-1" || user.Nickname != "octocat" || user.Name != "Example User" || user.Email != "user@example.com" || user.AvatarURL == "" {
		t.Fatalf("user = %+v", user)
	}
	if user.Token.AccessToken != "access-token" || user.Token.RefreshToken != "refresh-token" || user.Token.TokenType != "Bearer" || user.Token.Expiry.IsZero() {
		t.Fatalf("token = %+v", user.Token)
	}
	if !slicesEqual(user.Token.Scopes, []string{"profile", "email"}) {
		t.Fatalf("scopes = %v", user.Token.Scopes)
	}
	if string(user.Raw) != `{"id":"user-1","login":"octocat","name":"Example User","email":"user@example.com","avatar":"https://example.com/avatar.png"}` {
		t.Fatalf("raw user = %s", user.Raw)
	}
}

func TestUserFromExistingToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer existing-access-token" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		writeJSON(writer, `{"id":"existing-user"}`)
	}))
	defer server.Close()
	provider := newTestProvider(t, server.URL, func(config *oauth2provider.Config) {
		config.UserEndpoint = server.URL
	})
	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "existing-access-token"})
	if err != nil {
		t.Fatalf("User() error = %v", err)
	}
	if user.ID != "existing-user" || user.Token.AccessToken != "existing-access-token" {
		t.Fatalf("User() = %+v", user)
	}
}

func TestTokenRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		if request.Form.Get("grant_type") != "refresh_token" || request.Form.Get("refresh_token") != "old-refresh-token" {
			t.Errorf("refresh form = %v", request.Form)
		}
		writeJSON(writer, `{"access_token":"new-access-token","refresh_token":"new-refresh-token","token_type":"Bearer","scope":["profile","email"]}`)
	}))
	defer server.Close()
	provider := newTestProvider(t, server.URL)
	token, err := provider.Refresh(context.Background(), gociconnect.RefreshRequest{RefreshToken: "old-refresh-token"})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if token.AccessToken != "new-access-token" || token.RefreshToken != "new-refresh-token" || !slicesEqual(token.Scopes, []string{"profile", "email"}) {
		t.Fatalf("Refresh() = %+v", token)
	}
}

func TestUnsupportedTokenRefresh(t *testing.T) {
	provider := newTestProvider(t, "https://provider.example", func(config *oauth2provider.Config) {
		config.Capabilities.TokenRefresh = false
	})
	_, err := provider.Refresh(context.Background(), gociconnect.RefreshRequest{RefreshToken: "refresh-token"})
	if !errors.Is(err, gociconnect.ErrUnsupported) {
		t.Fatalf("Refresh() error = %v", err)
	}
}

func TestInjectedUserLoader(t *testing.T) {
	provider := newTestProvider(t, "https://provider.example", func(config *oauth2provider.Config) {
		config.UserEndpoint = ""
		config.UserMapper = nil
		config.UserLoader = oauth2provider.UserLoaderFunc(func(_ context.Context, _ oauth2provider.Fetcher, token gociconnect.Token) (gociconnect.User, error) {
			if token.AccessToken != "loader-access-token" {
				return gociconnect.User{}, errors.New("unexpected token")
			}
			return gociconnect.User{ID: "loader-user", Raw: json.RawMessage(`{"source":"loader"}`)}, nil
		})
	})
	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "loader-access-token"})
	if err != nil {
		t.Fatalf("User() error = %v", err)
	}
	if user.Provider != "example" || user.ID != "loader-user" || user.Token.AccessToken != "loader-access-token" || string(user.Raw) != `{"source":"loader"}` {
		t.Fatalf("User() = %+v", user)
	}
}

func TestUserLoadingHonorsCancellationAfterLoaderReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	provider := newTestProvider(t, "https://provider.example", func(config *oauth2provider.Config) {
		config.UserEndpoint = ""
		config.UserMapper = nil
		config.UserLoader = oauth2provider.UserLoaderFunc(func(_ context.Context, _ oauth2provider.Fetcher, _ gociconnect.Token) (gociconnect.User, error) {
			cancel()
			return gociconnect.User{ID: "canceled-user"}, nil
		})
	})

	_, err := provider.User(ctx, gociconnect.UserRequest{AccessToken: "access-token"})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, gociconnect.ErrTransport) {
		t.Fatalf("User() error = %v", err)
	}
}

func TestProviderCapabilities(t *testing.T) {
	provider := newTestProvider(t, "https://provider.example")
	capabilities := provider.Capabilities()
	if !capabilities.PKCE || !capabilities.TokenRefresh {
		t.Fatalf("Capabilities() = %+v", capabilities)
	}

	withoutPKCE := newTestProvider(t, "https://provider.example", func(config *oauth2provider.Config) {
		config.Capabilities.PKCE = false
	})
	authorization, err := withoutPKCE.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	query := parseAuthorizationQuery(t, authorization.URL)
	if authorization.Session.PKCEVerifier != "" || query.Get("code_challenge") != "" || query.Get("code_challenge_method") != "" {
		t.Fatalf("PKCE-disabled authorization = %+v, %v", authorization.Session, query)
	}
}

func validConfig(providerURL string) oauth2provider.Config {
	return oauth2provider.Config{
		Name:         "example",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://app.example/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:   providerURL + "/authorize",
			TokenURL:  providerURL + "/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		UserEndpoint: providerURL + "/user",
		UserMapper:   oauth2provider.UserMapperFunc(testMapper),
	}
}

func parseAuthorizationQuery(t *testing.T, authorizationURL string) url.Values {
	t.Helper()
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	return parsed.Query()
}

func assertPKCEChallenge(t *testing.T, query url.Values, verifier string) {
	t.Helper()
	if verifier == "" {
		t.Fatal("PKCE verifier is empty")
	}
	digest := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(digest[:])
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") != want {
		t.Fatalf("PKCE query = %v, want challenge %q", query, want)
	}
	if query.Get("code_challenge") == verifier {
		t.Fatal("PKCE challenge used the plain verifier")
	}
}

func writeJSON(writer http.ResponseWriter, body string) {
	writer.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(writer, body)
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestConcurrentProviderUse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/user" {
			http.NotFound(writer, request)
			return
		}
		writeJSON(writer, `{"id":"concurrent-user"}`)
	}))
	defer server.Close()

	var clockCalls int
	provider := newTestProvider(t, server.URL, func(config *oauth2provider.Config) {
		config.Random = deterministicRandom(400)
		config.Now = func() time.Time {
			clockCalls++
			return time.Unix(int64(clockCalls), 0)
		}
	})

	const calls = 100
	errorsChannel := make(chan error, calls*2)
	var wait sync.WaitGroup
	for range calls {
		wait.Add(2)
		go func() {
			defer wait.Done()
			authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
			if err != nil {
				errorsChannel <- err
				return
			}
			if authorization.Session.State == "" || authorization.Session.PKCEVerifier == "" {
				errorsChannel <- errors.New("incomplete authorization session")
			}
		}()
		go func() {
			defer wait.Done()
			user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "concurrent-access-token"})
			if err != nil {
				errorsChannel <- err
				return
			}
			if user.ID != "concurrent-user" {
				errorsChannel <- fmt.Errorf("user ID = %q", user.ID)
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
	if clockCalls != calls {
		t.Fatalf("clock calls = %d, want %d", clockCalls, calls)
	}
}
