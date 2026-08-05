// Package github implements GitHub social authentication.
package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	gociconnect "github.com/only1enes/goci-connect"
	"github.com/only1enes/goci-connect/oauth2provider"
	"golang.org/x/oauth2"
)

const defaultAPIURL = "https://api.github.com"

// Config configures the GitHub provider.
type Config struct {
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	Scopes          []string
	Endpoint        oauth2.Endpoint
	APIURL          string
	HTTPClient      *http.Client
	Random          io.Reader
	Now             func() time.Time
	MaxResponseSize int64
}

func (config Config) String() string {
	return fmt.Sprintf("{ClientID:%q ClientSecret:<redacted> RedirectURL:%q Scopes:%v Endpoint:%v APIURL:%q MaxResponseSize:%d}", config.ClientID, config.RedirectURL, config.Scopes, config.Endpoint, config.APIURL, config.MaxResponseSize)
}

func (config Config) GoString() string { return config.String() }

// New creates a concurrency-safe GitHub provider.
func New(config Config) (*oauth2provider.Base, error) {
	endpoint := config.Endpoint
	if endpoint.AuthURL == "" {
		endpoint.AuthURL = "https://github.com/login/oauth/authorize"
	}
	if endpoint.TokenURL == "" {
		endpoint.TokenURL = "https://github.com/login/oauth/access_token"
	}
	apiURL := strings.TrimRight(config.APIURL, "/")
	if apiURL == "" {
		apiURL = defaultAPIURL
	}
	scopes := config.Scopes
	if len(scopes) == 0 {
		scopes = []string{"read:user", "user:email"}
	}
	return oauth2provider.New(oauth2provider.Config{
		Name:            "github",
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
		UserResolver:    githubResolver{userURL: apiURL + "/user", emailsURL: apiURL + "/user/emails"},
	})
}

type githubResolver struct {
	userURL   string
	emailsURL string
}

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (resolver githubResolver) Resolve(ctx context.Context, fetcher oauth2provider.Fetcher, _ gociconnect.Token) (gociconnect.User, error) {
	var providerUser githubUser
	raw, err := fetcher.GetJSON(ctx, resolver.userURL, &providerUser)
	if err != nil {
		return gociconnect.User{}, err
	}
	if providerUser.Email == "" {
		providerUser.Email, err = resolver.verifiedEmail(ctx, fetcher)
		if err != nil {
			return gociconnect.User{}, err
		}
	}
	return gociconnect.User{
		ID:        strconv.FormatInt(providerUser.ID, 10),
		Nickname:  providerUser.Login,
		Name:      providerUser.Name,
		Email:     providerUser.Email,
		AvatarURL: providerUser.AvatarURL,
		Raw:       raw,
	}, nil
}

func (resolver githubResolver) verifiedEmail(ctx context.Context, fetcher oauth2provider.Fetcher) (string, error) {
	var emails []githubEmail
	if _, err := fetcher.GetJSON(ctx, resolver.emailsURL, &emails); err != nil {
		return "", err
	}
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}
	for _, email := range emails {
		if email.Verified {
			return email.Email, nil
		}
	}
	return "", nil
}
