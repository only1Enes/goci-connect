package oauth2provider_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gociconnect "github.com/only1enes/goci-connect"
	"github.com/only1enes/goci-connect/oauth2provider"
)

func TestNonSuccessfulProviderResponses(t *testing.T) {
	t.Run("token exchange", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/token" {
				http.NotFound(writer, request)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(writer, `{"error":"invalid_grant","error_description":"authorization-code-secret client-secret"}`)
		}))
		defer server.Close()
		provider := newTestProvider(t, server.URL)
		_, err := provider.Complete(context.Background(), validCompleteRequest())
		if !errors.Is(err, gociconnect.ErrTokenExchange) {
			t.Fatalf("Complete() error = %v", err)
		}
		assertErrorRedacts(t, err, "authorization-code-secret", "client-secret", "state-secret", "pkce-verifier-secret")
	})

	t.Run("token refresh", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(writer, `{"error":"invalid_grant","error_description":"refresh-token-secret"}`)
		}))
		defer server.Close()
		provider := newTestProvider(t, server.URL)
		_, err := provider.Refresh(context.Background(), gociconnect.RefreshRequest{RefreshToken: "refresh-token-secret"})
		if !errors.Is(err, gociconnect.ErrTokenRefresh) {
			t.Fatalf("Refresh() error = %v", err)
		}
		assertErrorRedacts(t, err, "refresh-token-secret", "client-secret")
	})

	t.Run("user endpoint", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(writer, "access-token-secret")
		}))
		defer server.Close()
		provider := newTestProvider(t, server.URL, func(config *oauth2provider.Config) {
			config.UserEndpoint = server.URL
		})
		_, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token-secret"})
		if !errors.Is(err, gociconnect.ErrProviderResponse) {
			t.Fatalf("User() error = %v", err)
		}
		assertErrorRedacts(t, err, "access-token-secret")
	})
}

func TestMalformedResponses(t *testing.T) {
	t.Run("token JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, "{")
		}))
		defer server.Close()
		provider := newTestProvider(t, server.URL)
		_, err := provider.Complete(context.Background(), validCompleteRequest())
		if !errors.Is(err, gociconnect.ErrTokenExchange) {
			t.Fatalf("Complete() error = %v", err)
		}
	})

	t.Run("user JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(writer, "{")
		}))
		defer server.Close()
		provider := newTestProvider(t, server.URL, func(config *oauth2provider.Config) {
			config.UserEndpoint = server.URL
		})
		_, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token"})
		if !errors.Is(err, gociconnect.ErrDecoding) {
			t.Fatalf("User() error = %v", err)
		}
	})

	t.Run("user mapping", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writeJSON(writer, `{"id":"user"}`)
		}))
		defer server.Close()
		provider := newTestProvider(t, server.URL, func(config *oauth2provider.Config) {
			config.UserEndpoint = server.URL
			config.UserMapper = oauth2provider.UserMapperFunc(func(json.RawMessage) (gociconnect.User, error) {
				return gociconnect.User{}, errors.New("raw-user-secret")
			})
		})
		_, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token"})
		if !errors.Is(err, gociconnect.ErrDecoding) {
			t.Fatalf("User() error = %v", err)
		}
		assertErrorRedacts(t, err, "raw-user-secret", "access-token")
	})
}

func TestResponseSizeLimits(t *testing.T) {
	t.Run("token response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writeJSON(writer, `{"access_token":"this-token-response-is-intentionally-larger-than-the-limit","token_type":"Bearer"}`)
		}))
		defer server.Close()
		provider := newTestProvider(t, server.URL, func(config *oauth2provider.Config) {
			config.MaxResponseSize = 32
		})
		_, err := provider.Complete(context.Background(), validCompleteRequest())
		if !errors.Is(err, gociconnect.ErrResponseTooLarge) {
			t.Fatalf("Complete() error = %v", err)
		}
	})

	t.Run("user response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writeJSON(writer, `{"id":"this-user-response-is-larger-than-the-limit"}`)
		}))
		defer server.Close()
		provider := newTestProvider(t, server.URL, func(config *oauth2provider.Config) {
			config.UserEndpoint = server.URL
			config.MaxResponseSize = 16
		})
		_, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token"})
		if !errors.Is(err, gociconnect.ErrResponseTooLarge) {
			t.Fatalf("User() error = %v", err)
		}
	})
}

func TestContextCancellation(t *testing.T) {
	provider := newTestProvider(t, "https://provider.example")

	t.Run("token exchange", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := provider.Complete(ctx, validCompleteRequest())
		if !errors.Is(err, gociconnect.ErrTransport) || !errors.Is(err, context.Canceled) {
			t.Fatalf("Complete() error = %v", err)
		}
	})

	t.Run("user loading", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := provider.User(ctx, gociconnect.UserRequest{AccessToken: "access-token"})
		if !errors.Is(err, gociconnect.ErrTransport) || !errors.Is(err, context.Canceled) {
			t.Fatalf("User() error = %v", err)
		}
	})
}

func TestTransportFailure(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport-access-token-secret")
	})}
	provider := newTestProvider(t, "https://provider.example", func(config *oauth2provider.Config) {
		config.HTTPClient = client
	})
	_, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "access-token-secret"})
	if !errors.Is(err, gociconnect.ErrTransport) {
		t.Fatalf("User() error = %v", err)
	}
	assertErrorRedacts(t, err, "transport-access-token-secret", "access-token-secret")
}

func TestMissingTokenInputs(t *testing.T) {
	provider := newTestProvider(t, "https://provider.example")
	if _, err := provider.User(context.Background(), gociconnect.UserRequest{}); !errors.Is(err, gociconnect.ErrInvalidRequest) {
		t.Fatalf("User() error = %v", err)
	}
	if _, err := provider.Refresh(context.Background(), gociconnect.RefreshRequest{}); !errors.Is(err, gociconnect.ErrInvalidRequest) {
		t.Fatalf("Refresh() error = %v", err)
	}
	request := validCompleteRequest()
	request.Session.PKCEVerifier = ""
	if _, err := provider.Complete(context.Background(), request); !errors.Is(err, gociconnect.ErrInvalidRequest) {
		t.Fatalf("Complete() error = %v", err)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	typedNilMapper := oauth2provider.UserMapperFunc(nil)
	typedNilLoader := oauth2provider.UserLoaderFunc(nil)
	tests := []struct {
		name   string
		change func(*oauth2provider.Config)
	}{
		{name: "empty name", change: func(config *oauth2provider.Config) { config.Name = " " }},
		{name: "empty client ID", change: func(config *oauth2provider.Config) { config.ClientID = "" }},
		{name: "invalid authorization endpoint", change: func(config *oauth2provider.Config) { config.Endpoint.AuthURL = "javascript://provider.example" }},
		{name: "invalid token endpoint", change: func(config *oauth2provider.Config) { config.Endpoint.TokenURL = "/token" }},
		{name: "secret in token endpoint", change: func(config *oauth2provider.Config) { config.Endpoint.TokenURL += "?client_secret=unsafe" }},
		{name: "invalid redirect", change: func(config *oauth2provider.Config) { config.RedirectURL = "callback" }},
		{name: "invalid user endpoint", change: func(config *oauth2provider.Config) { config.UserEndpoint = "file:///user" }},
		{name: "token in user endpoint", change: func(config *oauth2provider.Config) { config.UserEndpoint += "?access_token=unsafe" }},
		{name: "missing mapper", change: func(config *oauth2provider.Config) { config.UserMapper = nil }},
		{name: "typed nil mapper", change: func(config *oauth2provider.Config) { config.UserMapper = typedNilMapper }},
		{name: "typed nil loader", change: func(config *oauth2provider.Config) {
			config.UserEndpoint = ""
			config.UserMapper = nil
			config.UserLoader = typedNilLoader
		}},
		{name: "loader and mapper", change: func(config *oauth2provider.Config) {
			config.UserLoader = oauth2provider.UserLoaderFunc(func(context.Context, oauth2provider.Fetcher, gociconnect.Token) (gociconnect.User, error) {
				return gociconnect.User{}, nil
			})
		}},
		{name: "negative response limit", change: func(config *oauth2provider.Config) { config.MaxResponseSize = -1 }},
		{name: "overflowing response limit", change: func(config *oauth2provider.Config) { config.MaxResponseSize = int64(^uint64(0) >> 1) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig("https://provider.example")
			test.change(&config)
			_, err := oauth2provider.New(config)
			if !errors.Is(err, gociconnect.ErrInvalidConfiguration) {
				t.Fatalf("New() error = %v", err)
			}
		})
	}
}

func TestConfigurationAndProviderFormattingRedactsSecrets(t *testing.T) {
	config := validConfig("https://provider.example")
	config.Name = "provider-secret"
	config.ClientID = "client-id-secret"
	config.ClientSecret = "client-secret"
	config.RedirectURL = "https://app.example/callback?state=state-secret"
	config.AuthorizationParameters = map[string][]string{"login_hint": {"user-secret"}}
	config.UserEndpoint = "https://provider.example/user?tenant=token-secret"
	provider, err := oauth2provider.New(config)
	if err != nil {
		t.Fatal(err)
	}
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x|%d|%v|%#v", config, config, config, config, config, config, config, provider, provider)
	for _, secret := range []string{"provider-secret", "client-id-secret", "client-secret", "state-secret", "user-secret", "token-secret"} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("formatting contains %q: %s", secret, formatted)
		}
	}
}

func validCompleteRequest() gociconnect.CompleteRequest {
	return gociconnect.CompleteRequest{
		Callback: gociconnect.Callback{Code: "authorization-code-secret", State: "state-secret"},
		Session:  gociconnect.AuthorizationSession{State: "state-secret", PKCEVerifier: "pkce-verifier-secret"},
	}
}

func assertErrorRedacts(t *testing.T, err error, secrets ...string) {
	t.Helper()
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x|%d", err, err, err, err, err, err, err)
	for _, secret := range secrets {
		if strings.Contains(formatted, secret) {
			t.Fatalf("error formatting contains %q: %s", secret, formatted)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
