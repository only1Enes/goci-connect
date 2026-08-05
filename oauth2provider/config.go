package oauth2provider

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	gociconnect "github.com/only1enes/goci-connect"
	"golang.org/x/oauth2"
)

const (
	// DefaultMaxResponseSize is the default maximum token or user response body.
	DefaultMaxResponseSize int64 = 1 << 20
	defaultHTTPTimeout           = 15 * time.Second
)

// Capabilities declares optional protocol behavior supported by a provider.
type Capabilities struct {
	PKCE         bool
	TokenRefresh bool
}

// Config defines an immutable OAuth 2.0 provider after New returns.
type Config struct {
	Name                    string
	ClientID                string
	ClientSecret            string
	RedirectURL             string
	Endpoint                oauth2.Endpoint
	DefaultScopes           []string
	Capabilities            Capabilities
	AuthorizationParameters url.Values
	HTTPClient              *http.Client
	Random                  io.Reader
	Now                     func() time.Time
	MaxResponseSize         int64
	UserEndpoint            string
	UserMapper              UserMapper
	UserLoader              UserLoader
}

func (config Config) String() string {
	return "{Name:<redacted> ClientID:<redacted> ClientSecret:<redacted> RedirectURL:<redacted> Endpoint:<redacted> DefaultScopes:<omitted> Capabilities:<omitted> AuthorizationParameters:<omitted> HTTPClient:<omitted> Random:<omitted> Now:<omitted> MaxResponseSize:<omitted> UserEndpoint:<redacted> UserMapper:<omitted> UserLoader:<omitted>}"
}

func (config Config) GoString() string { return config.String() }

func (config Config) Format(state fmt.State, _ rune) {
	writeRedacted(state, config.String())
}

// Provider is a reusable, concurrency-safe OAuth 2.0 provider implementation.
type Provider struct {
	name                    string
	clientID                string
	clientSecret            string
	redirectURL             string
	endpoint                oauth2.Endpoint
	defaultScopes           []string
	capabilities            Capabilities
	authorizationParameters url.Values
	client                  *http.Client
	random                  io.Reader
	now                     func() time.Time
	maxResponseSize         int64
	userLoader              UserLoader
	randomMu                sync.Mutex
	nowMu                   sync.Mutex
}

var _ gociconnect.Provider = (*Provider)(nil)

// New validates and copies an OAuth 2.0 provider configuration.
func New(config Config) (*Provider, error) {
	name := strings.TrimSpace(config.Name)
	if name == "" || strings.TrimSpace(config.ClientID) == "" {
		return nil, configurationError(name, "create OAuth provider")
	}
	if !validHTTPURL(config.Endpoint.AuthURL) || !validHTTPURL(config.Endpoint.TokenURL) || !validRedirectURL(config.RedirectURL) {
		return nil, configurationError(name, "create OAuth provider")
	}
	if hasProtectedEndpointParameter(config.Endpoint.AuthURL) || hasSensitiveEndpointParameter(config.Endpoint.TokenURL) || invalidAuthorizationParameters(config.AuthorizationParameters) {
		return nil, configurationError(name, "create OAuth provider")
	}

	loader, err := configuredUserLoader(name, config)
	if err != nil {
		return nil, err
	}
	maxResponseSize := config.MaxResponseSize
	if maxResponseSize == 0 {
		maxResponseSize = DefaultMaxResponseSize
	}
	if maxResponseSize < 1 || maxResponseSize == int64(^uint64(0)>>1) {
		return nil, configurationError(name, "create OAuth provider")
	}

	client := config.HTTPClient
	if client == nil {
		client = &http.Client{
			Transport: cloneDefaultTransport(),
			Timeout:   defaultHTTPTimeout,
		}
	}
	clientCopy := *client
	transport := client.Transport
	if transport == nil {
		transport = cloneDefaultTransport()
	}
	clientCopy.Transport = &boundedTransport{base: transport, limit: maxResponseSize}

	randomReader := config.Random
	if randomReader == nil {
		randomReader = rand.Reader
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}

	return &Provider{
		name:                    name,
		clientID:                config.ClientID,
		clientSecret:            config.ClientSecret,
		redirectURL:             config.RedirectURL,
		endpoint:                config.Endpoint,
		defaultScopes:           cloneStrings(config.DefaultScopes),
		capabilities:            config.Capabilities,
		authorizationParameters: cloneValues(config.AuthorizationParameters),
		client:                  &clientCopy,
		random:                  randomReader,
		now:                     now,
		maxResponseSize:         maxResponseSize,
		userLoader:              loader,
	}, nil
}

// Name returns the provider's canonical registry name.
func (provider *Provider) Name() string {
	return provider.name
}

// Capabilities returns the provider's configured optional protocol behavior.
func (provider *Provider) Capabilities() Capabilities {
	return provider.capabilities
}

func (provider *Provider) String() string {
	if provider == nil {
		return "<nil>"
	}
	return "{Name:<redacted> ClientID:<redacted> ClientSecret:<redacted> RedirectURL:<redacted> Endpoint:<redacted> DefaultScopes:<omitted> Capabilities:<omitted> AuthorizationParameters:<omitted> HTTPClient:<omitted> UserLoader:<omitted>}"
}

func (provider *Provider) GoString() string { return provider.String() }

func (provider *Provider) Format(state fmt.State, _ rune) {
	writeRedacted(state, provider.String())
}

func configuredUserLoader(providerName string, config Config) (UserLoader, error) {
	hasLoader := !isNil(config.UserLoader)
	hasMapper := !isNil(config.UserMapper)
	if hasLoader {
		if hasMapper || strings.TrimSpace(config.UserEndpoint) != "" {
			return nil, configurationError(providerName, "create OAuth provider")
		}
		return config.UserLoader, nil
	}
	if !hasMapper || !validHTTPURL(config.UserEndpoint) || hasSensitiveEndpointParameter(config.UserEndpoint) {
		return nil, configurationError(providerName, "create OAuth provider")
	}
	return mappedUserLoader{endpoint: config.UserEndpoint, mapper: config.UserMapper}, nil
}

func configurationError(providerName, operation string) error {
	return gociconnect.NewError(gociconnect.ErrorCodeInvalidConfiguration, providerName, operation, nil)
}

func validHTTPURL(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.User == nil && parsed.Host != "" && (parsed.Scheme == "https" || parsed.Scheme == "http")
}

func validRedirectURL(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.User != nil || parsed.Scheme == "" {
		return false
	}
	if parsed.Scheme == "http" || parsed.Scheme == "https" {
		return parsed.Host != ""
	}
	return true
}

func hasProtectedEndpointParameter(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return true
	}
	return invalidAuthorizationParameters(parsed.Query())
}

func hasSensitiveEndpointParameter(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return true
	}
	for key := range parsed.Query() {
		if isSensitiveEndpointParameter(key) {
			return true
		}
	}
	return false
}

func invalidAuthorizationParameters(parameters url.Values) bool {
	for key := range parameters {
		if strings.TrimSpace(key) == "" {
			return true
		}
		if isProtectedAuthorizationParameter(key) {
			return true
		}
	}
	return false
}

func isProtectedAuthorizationParameter(key string) bool {
	switch strings.ToLower(key) {
	case "client_id", "client_secret", "code_challenge", "code_challenge_method", "code_verifier", "redirect_uri", "response_type", "scope", "state":
		return true
	default:
		return false
	}
}

func isSensitiveEndpointParameter(key string) bool {
	switch strings.ToLower(key) {
	case "access_token", "client_secret", "code", "code_verifier", "refresh_token":
		return true
	default:
		return false
	}
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return reflected.IsNil()
	default:
		return false
	}
}

func cloneDefaultTransport() http.RoundTripper {
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		return transport.Clone()
	}
	return http.DefaultTransport
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	clone := make([]string, len(values))
	copy(clone, values)
	return clone
}

func cloneValues(values url.Values) url.Values {
	if values == nil {
		return nil
	}
	clone := make(url.Values, len(values))
	for key, entries := range values {
		clone[key] = cloneStrings(entries)
	}
	return clone
}

func writeRedacted(state fmt.State, value string) {
	_, _ = state.Write([]byte(value))
}
