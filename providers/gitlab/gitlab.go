package gitlab

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	gociconnect "github.com/only1enes/goci-connect"
	"github.com/only1enes/goci-connect/oauth2provider"
	"golang.org/x/oauth2"
)

const (
	providerName     = "gitlab"
	defaultBaseURL   = "https://gitlab.com"
	defaultUserScope = "read_user"
)

// Config configures GitLab OAuth authentication. BaseURL defaults to
// https://gitlab.com and may identify an HTTPS GitLab Self-Managed instance.
type Config struct {
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	BaseURL         string
	Scopes          []string
	HTTPClient      *http.Client
	Random          io.Reader
	Now             func() time.Time
	MaxResponseSize int64
}

func (config Config) String() string {
	return "{ClientID:<redacted> ClientSecret:<redacted> RedirectURL:<redacted> BaseURL:<redacted> Scopes:<omitted> HTTPClient:<omitted> Random:<omitted> Now:<omitted> MaxResponseSize:<omitted>}"
}

func (config Config) GoString() string { return config.String() }

func (config Config) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(config.String()))
}

// New creates a concurrency-safe GitLab OAuth provider for GitLab.com or the
// configured GitLab Self-Managed instance.
func New(config Config) (*oauth2provider.Provider, error) {
	target, err := endpointsForBaseURL(config.BaseURL)
	if err != nil {
		return nil, err
	}
	return newWithEndpoints(config, target)
}

type endpoints struct {
	authorization string
	token         string
	currentUser   string
}

func endpointsForBaseURL(value string) (endpoints, error) {
	base, err := normalizeBaseURL(value)
	if err != nil {
		return endpoints{}, err
	}
	authorization, err := url.JoinPath(base, "oauth/authorize")
	if err != nil {
		return endpoints{}, configurationError("join GitLab authorization endpoint")
	}
	token, err := url.JoinPath(base, "oauth/token")
	if err != nil {
		return endpoints{}, configurationError("join GitLab token endpoint")
	}
	currentUser, err := url.JoinPath(base, "api/v4/user")
	if err != nil {
		return endpoints{}, configurationError("join GitLab user endpoint")
	}
	return endpoints{authorization: authorization, token: token, currentUser: currentUser}, nil
}

func normalizeBaseURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = defaultBaseURL
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", configurationError("validate GitLab base URL")
	}
	for _, segment := range strings.Split(parsed.EscapedPath(), "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil || decoded == "." || decoded == ".." || strings.ContainsAny(decoded, `/\`) {
			return "", configurationError("validate GitLab base URL")
		}
	}
	parsed.Scheme = "https"
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = strings.TrimRight(parsed.RawPath, "/")
	return parsed.String(), nil
}

func newWithEndpoints(config Config, target endpoints) (*oauth2provider.Provider, error) {
	if strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" || strings.TrimSpace(config.RedirectURL) == "" {
		return nil, configurationError("create GitLab provider")
	}
	scopes := config.Scopes
	if len(scopes) == 0 {
		scopes = []string{defaultUserScope}
	}
	return oauth2provider.New(oauth2provider.Config{
		Name:         providerName,
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:   target.authorization,
			TokenURL:  target.token,
			AuthStyle: oauth2.AuthStyleInParams,
		},
		DefaultScopes: scopes,
		Capabilities: oauth2provider.Capabilities{
			PKCE:         true,
			TokenRefresh: true,
		},
		HTTPClient:      config.HTTPClient,
		Random:          config.Random,
		Now:             config.Now,
		MaxResponseSize: config.MaxResponseSize,
		UserEndpoint:    target.currentUser,
		UserMapper:      oauth2provider.UserMapperFunc(mapUser),
	})
}

func configurationError(operation string) error {
	return gociconnect.NewError(gociconnect.ErrorCodeInvalidConfiguration, providerName, operation, nil)
}
