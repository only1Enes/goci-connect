package oauth2provider

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"

	gociconnect "github.com/only1enes/goci-connect"
	"golang.org/x/oauth2"
)

// Begin creates an authorization URL and the session values required by Complete.
func (provider *Provider) Begin(ctx context.Context, request gociconnect.BeginRequest) (gociconnect.Authorization, error) {
	if err := ctx.Err(); err != nil {
		return gociconnect.Authorization{}, provider.contextError("begin authorization", err)
	}
	if invalidAuthorizationParameters(request.Parameters) {
		return gociconnect.Authorization{}, gociconnect.NewError(gociconnect.ErrorCodeInvalidRequest, provider.name, "begin authorization", nil)
	}

	session := gociconnect.AuthorizationSession{
		StateVerificationDisabled: request.DisableState,
		CreatedAt:                 provider.currentTime(),
	}
	var err error
	if !request.DisableState {
		session.State, err = provider.randomValue(32)
		if err != nil {
			return gociconnect.Authorization{}, gociconnect.NewError(gociconnect.ErrorCodeInvalidConfiguration, provider.name, "generate authorization state", nil)
		}
	}

	options := make([]oauth2.AuthCodeOption, 0, 1)
	if provider.capabilities.PKCE {
		session.PKCEVerifier, err = provider.randomValue(32)
		if err != nil {
			return gociconnect.Authorization{}, gociconnect.NewError(gociconnect.ErrorCodeInvalidConfiguration, provider.name, "generate PKCE verifier", nil)
		}
		options = append(options, oauth2.S256ChallengeOption(session.PKCEVerifier))
	}

	configuration := provider.oauthConfig(request.Scopes)
	authorizationURL := configuration.AuthCodeURL(session.State, options...)
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		return gociconnect.Authorization{}, configurationError(provider.name, "build authorization URL")
	}
	query := parsed.Query()
	if request.DisableState {
		query.Del("state")
	}
	applyAuthorizationParameters(query, provider.authorizationParameters)
	applyAuthorizationParameters(query, request.Parameters)
	parsed.RawQuery = query.Encode()

	return gociconnect.Authorization{URL: parsed.String(), Session: session}, nil
}

// Complete validates a callback, exchanges its code, and loads the provider user.
func (provider *Provider) Complete(ctx context.Context, request gociconnect.CompleteRequest) (gociconnect.User, error) {
	if request.Callback.Error != "" {
		return gociconnect.User{}, gociconnect.NewError(gociconnect.ErrorCodeAuthorizationDenied, provider.name, "complete authorization", nil)
	}
	if strings.TrimSpace(request.Callback.Code) == "" {
		return gociconnect.User{}, gociconnect.NewError(gociconnect.ErrorCodeInvalidRequest, provider.name, "complete authorization", nil)
	}
	if !request.Session.StateVerificationDisabled && !validState(request.Session.State, request.Callback.State) {
		return gociconnect.User{}, gociconnect.NewError(gociconnect.ErrorCodeStateValidation, provider.name, "complete authorization", nil)
	}
	if provider.capabilities.PKCE && request.Session.PKCEVerifier == "" {
		return gociconnect.User{}, gociconnect.NewError(gociconnect.ErrorCodeInvalidRequest, provider.name, "complete authorization", nil)
	}

	options := make([]oauth2.AuthCodeOption, 0, 1)
	if provider.capabilities.PKCE {
		options = append(options, oauth2.VerifierOption(request.Session.PKCEVerifier))
	}
	oauthContext := context.WithValue(ctx, oauth2.HTTPClient, provider.client)
	token, err := provider.oauthConfig(nil).Exchange(oauthContext, request.Callback.Code, options...)
	if err != nil {
		return gociconnect.User{}, provider.tokenOperationError(ctx, gociconnect.ErrorCodeTokenExchange, "exchange authorization code", err)
	}
	return provider.loadUser(ctx, normalizeToken(token))
}

// User loads a provider user using an existing access token.
func (provider *Provider) User(ctx context.Context, request gociconnect.UserRequest) (gociconnect.User, error) {
	if strings.TrimSpace(request.AccessToken) == "" {
		return gociconnect.User{}, gociconnect.NewError(gociconnect.ErrorCodeInvalidRequest, provider.name, "load user from token", nil)
	}
	return provider.loadUser(ctx, gociconnect.Token{AccessToken: request.AccessToken})
}

// Refresh exchanges a refresh token when token refresh capability is enabled.
func (provider *Provider) Refresh(ctx context.Context, request gociconnect.RefreshRequest) (gociconnect.Token, error) {
	if !provider.capabilities.TokenRefresh {
		return gociconnect.Token{}, gociconnect.NewError(gociconnect.ErrorCodeUnsupported, provider.name, "refresh token", nil)
	}
	if strings.TrimSpace(request.RefreshToken) == "" {
		return gociconnect.Token{}, gociconnect.NewError(gociconnect.ErrorCodeInvalidRequest, provider.name, "refresh token", nil)
	}

	oauthContext := context.WithValue(ctx, oauth2.HTTPClient, provider.client)
	configuration := provider.oauthConfig(nil)
	source := configuration.TokenSource(oauthContext, &oauth2.Token{RefreshToken: request.RefreshToken})
	token, err := source.Token()
	if err != nil {
		return gociconnect.Token{}, provider.tokenOperationError(ctx, gociconnect.ErrorCodeTokenRefresh, "refresh token", err)
	}
	return normalizeToken(token), nil
}

func (provider *Provider) loadUser(ctx context.Context, token gociconnect.Token) (gociconnect.User, error) {
	if err := ctx.Err(); err != nil {
		return gociconnect.User{}, provider.contextError("load provider user", err)
	}
	fetcher := &apiFetcher{
		providerName:    provider.name,
		accessToken:     token.AccessToken,
		client:          provider.client,
		maxResponseSize: provider.maxResponseSize,
	}
	user, err := provider.userLoader.LoadUser(ctx, fetcher, token.Clone())
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return gociconnect.User{}, provider.contextError("load provider user", ctxErr)
		}
		if code, ok := gociconnect.ErrorCodeOf(err); ok {
			return gociconnect.User{}, gociconnect.NewError(code, provider.name, "load provider user", nil)
		}
		return gociconnect.User{}, gociconnect.NewError(gociconnect.ErrorCodeDecoding, provider.name, "load provider user", nil)
	}
	user.Provider = provider.name
	user.Token = token.Clone()
	return user.Clone(), nil
}

func (provider *Provider) oauthConfig(scopes []string) *oauth2.Config {
	if len(scopes) == 0 {
		scopes = provider.defaultScopes
	}
	return &oauth2.Config{
		ClientID:     provider.clientID,
		ClientSecret: provider.clientSecret,
		RedirectURL:  provider.redirectURL,
		Endpoint:     provider.endpoint,
		Scopes:       cloneStrings(scopes),
	}
}

func (provider *Provider) randomValue(size int) (string, error) {
	buffer := make([]byte, size)
	provider.randomMu.Lock()
	defer provider.randomMu.Unlock()
	if _, err := io.ReadFull(provider.random, buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func (provider *Provider) currentTime() time.Time {
	provider.nowMu.Lock()
	defer provider.nowMu.Unlock()
	return provider.now()
}

func (provider *Provider) tokenOperationError(ctx context.Context, code gociconnect.ErrorCode, operation string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return provider.contextError(operation, ctxErr)
	}
	if errors.Is(err, errResponseTooLarge) {
		return gociconnect.NewError(gociconnect.ErrorCodeResponseTooLarge, provider.name, operation, nil)
	}
	return gociconnect.NewError(code, provider.name, operation, nil)
}

func (provider *Provider) contextError(operation string, cause error) error {
	return gociconnect.NewError(gociconnect.ErrorCodeTransport, provider.name, operation, cause)
}

func validState(expected, received string) bool {
	if expected == "" || received == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(received)) == 1
}

func applyAuthorizationParameters(query, parameters url.Values) {
	for key, values := range parameters {
		query.Del(key)
		for _, value := range values {
			query.Add(key, value)
		}
	}
}

func normalizeToken(token *oauth2.Token) gociconnect.Token {
	return gociconnect.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry,
		Scopes:       extractScopes(token.Extra("scope")),
	}
}

func extractScopes(value any) []string {
	switch scopes := value.(type) {
	case string:
		return splitScopeString(scopes)
	case []string:
		return cloneStrings(scopes)
	case []any:
		result := make([]string, 0, len(scopes))
		for _, scope := range scopes {
			if text, ok := scope.(string); ok {
				result = append(result, text)
			}
		}
		return result
	case json.RawMessage:
		var text string
		if json.Unmarshal(scopes, &text) == nil {
			return splitScopeString(text)
		}
		var values []string
		if json.Unmarshal(scopes, &values) == nil {
			return values
		}
		return nil
	default:
		return nil
	}
}

func splitScopeString(value string) []string {
	scopes := strings.FieldsFunc(value, func(character rune) bool {
		return character == ',' || character == ' ' || character == '\t' || character == '\r' || character == '\n'
	})
	if scopes == nil {
		return []string{}
	}
	return scopes
}
