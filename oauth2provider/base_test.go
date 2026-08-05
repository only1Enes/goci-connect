package oauth2provider_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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

type testUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func userResolver(endpoint string) oauth2provider.UserResolver {
	return oauth2provider.UserResolverFunc(func(ctx context.Context, fetcher oauth2provider.Fetcher, _ gociconnect.Token) (gociconnect.User, error) {
		var value testUser
		raw, err := fetcher.GetJSON(ctx, endpoint, &value)
		if err != nil {
			return gociconnect.User{}, err
		}
		return gociconnect.User{ID: value.ID, Name: value.Name, Raw: raw}, nil
	})
}

func newBase(t *testing.T, serverURL string, options ...func(*oauth2provider.Config)) *oauth2provider.Base {
	t.Helper()
	config := oauth2provider.Config{
		Name:         "example",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://app.example/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:   serverURL + "/authorize",
			TokenURL:  serverURL + "/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		DefaultScopes: []string{"profile"},
		PKCE:          true,
		HTTPClient:    &http.Client{Timeout: time.Second},
		Random: bytes.NewReader(append(
			bytes.Repeat([]byte{0x5a}, 32),
			bytes.Repeat([]byte{0x6b}, 224)...,
		)),
		Now:          func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		UserResolver: userResolver(serverURL + "/user"),
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

func TestBeginGeneratesStateAndS256PKCE(t *testing.T) {
	provider := newBase(t, "https://provider.example")
	authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{
		Scopes:     []string{"one", "two"},
		Parameters: url.Values{"prompt": {"consent"}},
	})
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	parsed, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("state") != authorization.Session.State || authorization.Session.State == "" {
		t.Fatalf("state query = %q, session = %q", query.Get("state"), authorization.Session.State)
	}
	if query.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q", query.Get("code_challenge_method"))
	}
	digest := sha256.Sum256([]byte(authorization.Session.PKCEVerifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if query.Get("code_challenge") != wantChallenge {
		t.Fatalf("code_challenge = %q, want %q", query.Get("code_challenge"), wantChallenge)
	}
	if strings.Contains(authorization.URL, authorization.Session.PKCEVerifier) {
		t.Fatal("authorization URL contains the PKCE verifier")
	}
	if query.Get("scope") != "one two" || query.Get("prompt") != "consent" {
		t.Fatalf("authorization query = %v", query)
	}
	if !authorization.Session.CreatedAt.Equal(time.Unix(1_700_000_000, 0)) {
		t.Fatalf("CreatedAt = %v", authorization.Session.CreatedAt)
	}
}

func TestBeginStateDisabledDoesNotDisablePKCE(t *testing.T) {
	provider := newBase(t, "https://provider.example")
	authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{DisableState: true})
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	parsed, _ := url.Parse(authorization.URL)
	if _, exists := parsed.Query()["state"]; exists {
		t.Fatalf("authorization URL unexpectedly contains state: %s", authorization.URL)
	}
	if authorization.Session.PKCEVerifier == "" || parsed.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("state-disabled authorization did not retain S256 PKCE")
	}
}

func TestBeginRejectsReservedParameters(t *testing.T) {
	provider := newBase(t, "https://provider.example")
	_, err := provider.Begin(context.Background(), gociconnect.BeginRequest{Parameters: url.Values{"state": {"chosen"}}})
	if !errors.Is(err, gociconnect.ErrInvalidRequest) {
		t.Fatalf("Begin() error = %v", err)
	}
}

func TestCompleteExchangesTokenAndRetrievesUser(t *testing.T) {
	var expectedVerifier string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			if err := request.ParseForm(); err != nil {
				t.Error(err)
			}
			if request.Form.Get("code") != "authorization-code" || request.Form.Get("code_verifier") != expectedVerifier {
				t.Errorf("token form = %v", request.Form)
			}
			writer.Header().Set("Content-Type", "application/json")
			io.WriteString(writer, `{"access_token":"access-secret","refresh_token":"refresh-secret","token_type":"Bearer","expires_in":3600,"scope":"profile email"}`)
		case "/user":
			if request.Header.Get("Authorization") != "Bearer access-secret" {
				t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
			}
			io.WriteString(writer, `{"id":"user-1","name":"Example User"}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	provider := newBase(t, server.URL)
	authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	expectedVerifier = authorization.Session.PKCEVerifier
	user, err := provider.Complete(context.Background(), gociconnect.CompleteRequest{
		Callback: gociconnect.Callback{Code: "authorization-code", State: authorization.Session.State},
		Session:  authorization.Session,
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if user.Provider != "example" || user.ID != "user-1" || user.Name != "Example User" {
		t.Fatalf("Complete() user = %+v", user)
	}
	if user.Token.AccessToken != "access-secret" || user.Token.RefreshToken != "refresh-secret" || user.Token.TokenType != "Bearer" {
		t.Fatalf("Complete() token = %+v", user.Token)
	}
	if strings.Join(user.Token.Scopes, " ") != "profile email" {
		t.Fatalf("token scopes = %v", user.Token.Scopes)
	}
	if !json.Valid(user.Raw) {
		t.Fatalf("raw user is invalid JSON: %s", user.Raw)
	}
}

func TestCompleteValidatesCallback(t *testing.T) {
	provider := newBase(t, "https://provider.example")
	tests := []struct {
		name    string
		request gociconnect.CompleteRequest
		want    error
	}{
		{name: "provider error", request: gociconnect.CompleteRequest{Callback: gociconnect.Callback{Error: "access_denied", ErrorDescription: "declined"}}, want: gociconnect.ErrAuthorizationDenied},
		{name: "missing code", request: gociconnect.CompleteRequest{}, want: gociconnect.ErrMissingCode},
		{name: "missing state", request: gociconnect.CompleteRequest{Callback: gociconnect.Callback{Code: "code"}, Session: gociconnect.AuthorizationSession{State: "expected", PKCEVerifier: "verifier"}}, want: gociconnect.ErrStateMismatch},
		{name: "wrong state", request: gociconnect.CompleteRequest{Callback: gociconnect.Callback{Code: "code", State: "wrong"}, Session: gociconnect.AuthorizationSession{State: "expected", PKCEVerifier: "verifier"}}, want: gociconnect.ErrStateMismatch},
		{name: "missing verifier", request: gociconnect.CompleteRequest{Callback: gociconnect.Callback{Code: "code", State: "expected"}, Session: gociconnect.AuthorizationSession{State: "expected"}}, want: gociconnect.ErrInvalidCallback},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := provider.Complete(context.Background(), test.request)
			if !errors.Is(err, test.want) {
				t.Fatalf("Complete() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		if request.Form.Get("grant_type") != "refresh_token" || request.Form.Get("refresh_token") != "old-refresh" {
			t.Errorf("refresh form = %v", request.Form)
		}
		writer.Header().Set("Content-Type", "application/json")
		io.WriteString(writer, `{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","scope":"profile"}`)
	}))
	defer server.Close()
	provider := newBase(t, server.URL)
	token, err := provider.Refresh(context.Background(), gociconnect.RefreshRequest{RefreshToken: "old-refresh"})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if token.AccessToken != "new-access" || token.RefreshToken != "new-refresh" {
		t.Fatalf("Refresh() token = %+v", token)
	}
}

func TestUserWithExistingToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer existing-secret" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		io.WriteString(writer, `{"id":"existing-user","name":"Existing"}`)
	}))
	defer server.Close()
	provider := newBase(t, server.URL, func(config *oauth2provider.Config) {
		config.UserResolver = userResolver(server.URL)
	})
	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "existing-secret"})
	if err != nil {
		t.Fatalf("User() error = %v", err)
	}
	if user.ID != "existing-user" || user.Token.AccessToken != "existing-secret" {
		t.Fatalf("User() = %+v", user)
	}
}

func TestUserResponseFailures(t *testing.T) {
	tests := []struct {
		name     string
		handler  http.HandlerFunc
		maxBytes int64
		want     error
	}{
		{name: "non-2xx", handler: func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "access-secret", http.StatusUnauthorized) }, want: gociconnect.ErrProviderResponse},
		{name: "malformed JSON", handler: func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "{") }, want: gociconnect.ErrMalformedResponse},
		{name: "oversized", handler: func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, `{"id":"too large"}`) }, maxBytes: 4, want: gociconnect.ErrResponseTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			provider := newBase(t, server.URL, func(config *oauth2provider.Config) {
				config.UserResolver = userResolver(server.URL)
				config.MaxResponseSize = test.maxBytes
			})
			_, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-secret"})
			if !errors.Is(err, test.want) {
				t.Fatalf("User() error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), "access-secret") {
				t.Fatalf("error exposes access token: %v", err)
			}
		})
	}
}

func TestUserContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()
	provider := newBase(t, server.URL, func(config *oauth2provider.Config) {
		config.UserResolver = userResolver(server.URL)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := provider.User(ctx, gociconnect.UserRequest{AccessToken: "access-secret"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("User() error = %v", err)
	}
}

func TestUserTransportError(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport failed")
	})}
	provider := newBase(t, "https://provider.example", func(config *oauth2provider.Config) {
		config.HTTPClient = client
	})
	_, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-secret"})
	if !errors.Is(err, gociconnect.ErrUserRetrieval) {
		t.Fatalf("User() error = %v", err)
	}
}

func TestTokenExchangeErrorRedactsSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadRequest)
		io.WriteString(writer, `{"error":"invalid_grant","error_description":"authorization-code client-secret verifier-secret"}`)
	}))
	defer server.Close()
	provider := newBase(t, server.URL)
	_, err := provider.Complete(context.Background(), gociconnect.CompleteRequest{
		Callback: gociconnect.Callback{Code: "authorization-code", State: "state"},
		Session:  gociconnect.AuthorizationSession{State: "state", PKCEVerifier: "verifier-secret"},
	})
	if !errors.Is(err, gociconnect.ErrTokenExchange) {
		t.Fatalf("Complete() error = %v", err)
	}
	for _, secret := range []string{"authorization-code", "client-secret", "verifier-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error exposes %q: %v", secret, err)
		}
	}
}

func TestNewValidatesConfiguration(t *testing.T) {
	tests := []oauth2provider.Config{
		{},
		{Name: "example", ClientID: "client", RedirectURL: "https://app.example/callback", Endpoint: oauth2.Endpoint{AuthURL: "javascript://provider.example/auth", TokenURL: "https://provider.example/token"}, UserResolver: userResolver("https://provider.example/user")},
	}
	for _, config := range tests {
		_, err := oauth2provider.New(config)
		if !errors.Is(err, gociconnect.ErrInvalidConfig) {
			t.Fatalf("New() error = %v", err)
		}
	}
}

func TestConcurrentBegin(t *testing.T) {
	provider := newBase(t, "https://provider.example", func(config *oauth2provider.Config) {
		config.Random = bytes.NewReader(bytes.Repeat([]byte{0x44}, 64*100))
	})
	var wait sync.WaitGroup
	for index := 0; index < 50; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
			if err != nil {
				t.Errorf("Begin() error = %v", err)
				return
			}
			if authorization.Session.State == "" || authorization.Session.PKCEVerifier == "" {
				t.Error("Begin() returned incomplete session")
			}
		}()
	}
	wait.Wait()
}

func TestConfigurationFormattingRedactsClientSecret(t *testing.T) {
	config := oauth2provider.Config{Name: "example", ClientID: "client", ClientSecret: "client-secret"}
	formatted := config.String() + config.GoString()
	if strings.Contains(formatted, "client-secret") {
		t.Fatalf("config formatting exposes client secret: %s", formatted)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
