package discord

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
	providerName          = "discord"
	authorizationEndpoint = "https://discord.com/oauth2/authorize"
	tokenEndpoint         = "https://discord.com/api/oauth2/token"
	currentUserEndpoint   = "https://discord.com/api/v10/users/@me"
	cdnBaseURL            = "https://cdn.discordapp.com"
	identifyScope         = "identify"
	emailScope            = "email"
)

// Config configures Discord OAuth authentication. The zero value for Scopes
// requests the identify and email scopes needed by the normalized user model.
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

// New creates a concurrency-safe Discord OAuth provider.
func New(config Config) (*oauth2provider.Provider, error) {
	return newWithEndpoints(config, endpoints{
		authorization: authorizationEndpoint,
		token:         tokenEndpoint,
		currentUser:   currentUserEndpoint,
	})
}

type endpoints struct {
	authorization string
	token         string
	currentUser   string
}

func newWithEndpoints(config Config, target endpoints) (*oauth2provider.Provider, error) {
	if strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" || strings.TrimSpace(config.RedirectURL) == "" {
		return nil, gociconnect.NewError(gociconnect.ErrorCodeInvalidConfiguration, providerName, "create Discord provider", nil)
	}
	scopes := config.Scopes
	if len(scopes) == 0 {
		scopes = []string{identifyScope, emailScope}
	}
	return oauth2provider.New(oauth2provider.Config{
		Name:         providerName,
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:   target.authorization,
			TokenURL:  target.token,
			AuthStyle: oauth2.AuthStyleInHeader,
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
