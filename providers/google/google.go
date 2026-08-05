package google

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
	providerName          = "google"
	authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	tokenEndpoint         = "https://oauth2.googleapis.com/token"
	userInfoEndpoint      = "https://openidconnect.googleapis.com/v1/userinfo"
	openIDScope           = "openid"
	profileScope          = "profile"
	emailScope            = "email"
)

// Config configures Google OAuth authentication. AuthorizationParameters may
// contain provider options such as access_type, prompt, login_hint, hd, and
// include_granted_scopes; protocol security parameters remain protected.
type Config struct {
	ClientID                string
	ClientSecret            string
	RedirectURL             string
	Scopes                  []string
	AuthorizationParameters url.Values
	HTTPClient              *http.Client
	Random                  io.Reader
	Now                     func() time.Time
	MaxResponseSize         int64
}

func (config Config) String() string {
	return "{ClientID:<redacted> ClientSecret:<redacted> RedirectURL:<redacted> Scopes:<omitted> AuthorizationParameters:<omitted> HTTPClient:<omitted> Random:<omitted> Now:<omitted> MaxResponseSize:<omitted>}"
}

func (config Config) GoString() string { return config.String() }

func (config Config) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(config.String()))
}

// New creates a concurrency-safe Google OAuth provider. User identity is
// loaded from Google's UserInfo endpoint using the exchanged access token.
func New(config Config) (*oauth2provider.Provider, error) {
	return newWithEndpoints(config, endpoints{
		authorization: authorizationEndpoint,
		token:         tokenEndpoint,
		userInfo:      userInfoEndpoint,
	})
}

type endpoints struct {
	authorization string
	token         string
	userInfo      string
}

func newWithEndpoints(config Config, target endpoints) (*oauth2provider.Provider, error) {
	if strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" || strings.TrimSpace(config.RedirectURL) == "" {
		return nil, gociconnect.NewError(gociconnect.ErrorCodeInvalidConfiguration, providerName, "create Google provider", nil)
	}
	scopes := config.Scopes
	if len(scopes) == 0 {
		scopes = []string{openIDScope, profileScope, emailScope}
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
		DefaultScopes:           scopes,
		AuthorizationParameters: config.AuthorizationParameters,
		Capabilities: oauth2provider.Capabilities{
			PKCE:         true,
			TokenRefresh: true,
		},
		HTTPClient:      config.HTTPClient,
		Random:          config.Random,
		Now:             config.Now,
		MaxResponseSize: config.MaxResponseSize,
		UserEndpoint:    target.userInfo,
		UserMapper:      oauth2provider.UserMapperFunc(mapUserInfo),
	})
}
