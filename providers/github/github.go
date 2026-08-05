package github

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	gociconnect "github.com/only1enes/goci-connect"
	"github.com/only1enes/goci-connect/oauth2provider"
	"golang.org/x/oauth2"
)

const (
	providerName          = "github"
	authorizationEndpoint = "https://github.com/login/oauth/authorize"
	tokenEndpoint         = "https://github.com/login/oauth/access_token"
	apiEndpoint           = "https://api.github.com"
)

// Config configures GitHub OAuth authentication. The zero value for Scopes
// requests only the public information GitHub exposes without OAuth scopes.
type Config struct {
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	Scopes          []string
	HTTPClient      *http.Client
	Random          io.Reader
	Now             func() time.Time
	MaxResponseSize int64
}

func (config Config) String() string {
	return "{ClientID:<redacted> ClientSecret:<redacted> RedirectURL:<redacted> Scopes:<omitted> HTTPClient:<omitted> Random:<omitted> Now:<omitted> MaxResponseSize:<omitted>}"
}

func (config Config) GoString() string { return config.String() }

func (config Config) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(config.String()))
}

// New creates a concurrency-safe GitHub OAuth provider.
func New(config Config) (*oauth2provider.Provider, error) {
	return newWithEndpoints(config, endpoints{
		authorization: authorizationEndpoint,
		token:         tokenEndpoint,
		api:           apiEndpoint,
	})
}

type endpoints struct {
	authorization string
	token         string
	api           string
}

func newWithEndpoints(config Config, target endpoints) (*oauth2provider.Provider, error) {
	if strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" || strings.TrimSpace(config.RedirectURL) == "" {
		return nil, gociconnect.NewError(gociconnect.ErrorCodeInvalidConfiguration, providerName, "create GitHub provider", nil)
	}
	api := strings.TrimRight(target.api, "/")
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
		DefaultScopes: config.Scopes,
		Capabilities: oauth2provider.Capabilities{
			PKCE: true,
		},
		HTTPClient:      config.HTTPClient,
		Random:          config.Random,
		Now:             config.Now,
		MaxResponseSize: config.MaxResponseSize,
		UserLoader: githubUserLoader{
			userEndpoint:  api + "/user",
			emailEndpoint: api + "/user/emails",
		},
	})
}
