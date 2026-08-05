package github

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	gociconnect "github.com/only1enes/goci-connect"
	"github.com/only1enes/goci-connect/oauth2provider"
)

type githubUserLoader struct {
	userEndpoint  string
	emailEndpoint string
}

type githubUser struct {
	ID        json.Number `json:"id"`
	Login     string      `json:"login"`
	Name      string      `json:"name"`
	Email     string      `json:"email"`
	AvatarURL string      `json:"avatar_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (loader githubUserLoader) LoadUser(ctx context.Context, fetcher oauth2provider.Fetcher, token gociconnect.Token) (gociconnect.User, error) {
	var source githubUser
	raw, err := fetcher.GetJSON(ctx, loader.userEndpoint, &source)
	if err != nil {
		return gociconnect.User{}, err
	}
	providerID := source.ID.String()
	if _, err := strconv.ParseUint(providerID, 10, 64); err != nil {
		return gociconnect.User{}, gociconnect.NewError(gociconnect.ErrorCodeDecoding, providerName, "map GitHub user", nil)
	}

	user := gociconnect.User{
		ID:        providerID,
		Nickname:  source.Login,
		Name:      source.Name,
		Email:     strings.TrimSpace(source.Email),
		AvatarURL: source.AvatarURL,
		Raw:       raw,
	}
	if user.Email == "" && canRequestEmails(token.Scopes) {
		email, ok, err := loader.fallbackEmail(ctx, fetcher)
		if err != nil {
			return gociconnect.User{}, err
		}
		if ok {
			user.Email = email
		}
	}
	return user, nil
}

func (loader githubUserLoader) fallbackEmail(ctx context.Context, fetcher oauth2provider.Fetcher) (string, bool, error) {
	var emails []githubEmail
	if _, err := fetcher.GetJSON(ctx, loader.emailEndpoint, &emails); err != nil {
		if ctx.Err() != nil {
			return "", false, err
		}
		// Email is optional, and existing tokens may not have user:email permission.
		return "", false, nil
	}
	for _, email := range emails {
		if email.Primary && email.Verified && strings.TrimSpace(email.Email) != "" {
			return strings.TrimSpace(email.Email), true, nil
		}
	}
	for _, email := range emails {
		if email.Verified && strings.TrimSpace(email.Email) != "" {
			return strings.TrimSpace(email.Email), true, nil
		}
	}
	return "", false, nil
}

func canRequestEmails(scopes []string) bool {
	if scopes == nil {
		return true
	}
	for _, scope := range scopes {
		if scope == "user" || scope == "user:email" {
			return true
		}
	}
	return false
}
