// Package google implements Google social authentication.
package google

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	gociconnect "github.com/only1enes/goci-connect"
	"github.com/only1enes/goci-connect/oauth2provider"
	"golang.org/x/oauth2"
)

// Config configures the Google provider.
type Config struct {
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	Scopes          []string
	Endpoint        oauth2.Endpoint
	UserInfoURL     string
	HTTPClient      *http.Client
	Random          io.Reader
	Now             func() time.Time
	MaxResponseSize int64
}

func (config Config) String() string {
	return fmt.Sprintf("{ClientID:%q ClientSecret:<redacted> RedirectURL:%q Scopes:%v Endpoint:%v UserInfoURL:%q MaxResponseSize:%d}", config.ClientID, config.RedirectURL, config.Scopes, config.Endpoint, config.UserInfoURL, config.MaxResponseSize)
}

func (config Config) GoString() string { return config.String() }

// New creates a concurrency-safe Google provider.
func New(config Config) (*oauth2provider.Base, error) {
	endpoint := config.Endpoint
	if endpoint.AuthURL == "" {
		endpoint.AuthURL = "https://accounts.google.com/o/oauth2/auth"
	}
	if endpoint.TokenURL == "" {
		endpoint.TokenURL = "https://oauth2.googleapis.com/token"
	}
	userInfoURL := config.UserInfoURL
	if userInfoURL == "" {
		userInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
	}
	scopes := config.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	return oauth2provider.New(oauth2provider.Config{
		Name:            "google",
		ClientID:        config.ClientID,
		ClientSecret:    config.ClientSecret,
		RedirectURL:     config.RedirectURL,
		Endpoint:        endpoint,
		DefaultScopes:   scopes,
		PKCE:            true,
		HTTPClient:      config.HTTPClient,
		Random:          config.Random,
		Now:             config.Now,
		MaxResponseSize: config.MaxResponseSize,
		UserResolver:    googleResolver{userInfoURL: userInfoURL},
	})
}

type googleResolver struct {
	userInfoURL string
}

type googleUser struct {
	Subject string `json:"sub"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture string `json:"picture"`
}

func (resolver googleResolver) Resolve(ctx context.Context, fetcher oauth2provider.Fetcher, _ gociconnect.Token) (gociconnect.User, error) {
	var providerUser googleUser
	raw, err := fetcher.GetJSON(ctx, resolver.userInfoURL, &providerUser)
	if err != nil {
		return gociconnect.User{}, err
	}
	return gociconnect.User{
		ID:        providerUser.Subject,
		Name:      providerUser.Name,
		Email:     providerUser.Email,
		AvatarURL: providerUser.Picture,
		Raw:       raw,
	}, nil
}
