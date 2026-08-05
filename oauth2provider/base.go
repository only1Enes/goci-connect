// Package oauth2provider provides a reusable, concurrency-safe OAuth 2.0 provider foundation.
package oauth2provider

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	gociconnect "github.com/only1enes/goci-connect"
	"golang.org/x/oauth2"
)

const defaultMaxResponseSize int64 = 1 << 20

var reservedAuthorizationParameters = map[string]struct{}{
	"client_id":             {},
	"code_challenge":        {},
	"code_challenge_method": {},
	"redirect_uri":          {},
	"response_type":         {},
	"scope":                 {},
	"state":                 {},
}

// Fetcher performs authenticated, bounded provider API requests.
type Fetcher interface {
	GetJSON(context.Context, string, any) (json.RawMessage, error)
}

// UserResolver maps provider API responses into normalized users.
type UserResolver interface {
	Resolve(context.Context, Fetcher, gociconnect.Token) (gociconnect.User, error)
}

// UserResolverFunc adapts a function into a UserResolver.
type UserResolverFunc func(context.Context, Fetcher, gociconnect.Token) (gociconnect.User, error)

func (resolver UserResolverFunc) Resolve(ctx context.Context, fetcher Fetcher, token gociconnect.Token) (gociconnect.User, error) {
	return resolver(ctx, fetcher, token)
}

// Config configures an OAuth 2.0 provider. Values are copied by New.
type Config struct {
	Name            string
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	Endpoint        oauth2.Endpoint
	DefaultScopes   []string
	PKCE            bool
	HTTPClient      *http.Client
	Random          io.Reader
	Now             func() time.Time
	MaxResponseSize int64
	UserResolver    UserResolver
}

func (config Config) String() string {
	return fmt.Sprintf("{Name:%q ClientID:%q ClientSecret:<redacted> RedirectURL:%q Endpoint:%v DefaultScopes:%v PKCE:%t MaxResponseSize:%d}", config.Name, config.ClientID, config.RedirectURL, config.Endpoint, config.DefaultScopes, config.PKCE, config.MaxResponseSize)
}

func (config Config) GoString() string { return config.String() }

// Base implements secure OAuth authorization, token, and user operations.
type Base struct {
	name            string
	clientID        string
	clientSecret    string
	redirectURL     string
	endpoint        oauth2.Endpoint
	defaultScopes   []string
	pkce            bool
	httpClient      *http.Client
	random          io.Reader
	now             func() time.Time
	maxResponseSize int64
	userResolver    UserResolver
	randomMu        sync.Mutex
	nowMu           sync.Mutex
}

func (provider *Base) String() string {
	return fmt.Sprintf("{Name:%q ClientID:%q ClientSecret:<redacted> RedirectURL:%q Endpoint:%v DefaultScopes:%v PKCE:%t MaxResponseSize:%d}", provider.name, provider.clientID, provider.redirectURL, provider.endpoint, provider.defaultScopes, provider.pkce, provider.maxResponseSize)
}

func (provider *Base) GoString() string { return provider.String() }

// New validates and copies an OAuth provider configuration.
func New(config Config) (*Base, error) {
	name := strings.ToLower(strings.TrimSpace(config.Name))
	if name == "" || strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.RedirectURL) == "" {
		return nil, &gociconnect.Error{Kind: gociconnect.ErrInvalidConfig, Op: "create OAuth provider", Provider: name, Message: "name, client ID, and redirect URL are required"}
	}
	if !validHTTPURL(config.Endpoint.AuthURL) {
		return nil, &gociconnect.Error{Kind: gociconnect.ErrInvalidConfig, Op: "create OAuth provider", Provider: name, Message: "authorization endpoint is invalid"}
	}
	if !validHTTPURL(config.Endpoint.TokenURL) {
		return nil, &gociconnect.Error{Kind: gociconnect.ErrInvalidConfig, Op: "create OAuth provider", Provider: name, Message: "token endpoint is invalid"}
	}
	if !validAbsoluteURL(config.RedirectURL) {
		return nil, &gociconnect.Error{Kind: gociconnect.ErrInvalidConfig, Op: "create OAuth provider", Provider: name, Message: "redirect URL is invalid"}
	}
	if config.UserResolver == nil {
		return nil, &gociconnect.Error{Kind: gociconnect.ErrInvalidConfig, Op: "create OAuth provider", Provider: name, Message: "user resolver is required"}
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	randomReader := config.Random
	if randomReader == nil {
		randomReader = rand.Reader
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	maxResponseSize := config.MaxResponseSize
	if maxResponseSize == 0 {
		maxResponseSize = defaultMaxResponseSize
	}
	if maxResponseSize < 1 {
		return nil, &gociconnect.Error{Kind: gociconnect.ErrInvalidConfig, Op: "create OAuth provider", Provider: name, Message: "maximum response size must be positive"}
	}
	return &Base{
		name:            name,
		clientID:        config.ClientID,
		clientSecret:    config.ClientSecret,
		redirectURL:     config.RedirectURL,
		endpoint:        config.Endpoint,
		defaultScopes:   append([]string(nil), config.DefaultScopes...),
		pkce:            config.PKCE,
		httpClient:      client,
		random:          randomReader,
		now:             now,
		maxResponseSize: maxResponseSize,
		userResolver:    config.UserResolver,
	}, nil
}

// Name returns the provider registry name.
func (provider *Base) Name() string {
	return provider.name
}

// Begin creates a provider authorization URL and its matching session.
func (provider *Base) Begin(_ context.Context, request gociconnect.BeginRequest) (gociconnect.Authorization, error) {
	for key := range request.Parameters {
		if _, reserved := reservedAuthorizationParameters[strings.ToLower(key)]; reserved {
			return gociconnect.Authorization{}, &gociconnect.Error{Kind: gociconnect.ErrInvalidRequest, Op: "begin authorization", Provider: provider.name, Message: fmt.Sprintf("authorization parameter %q is reserved", key)}
		}
	}

	session := gociconnect.AuthorizationSession{
		StateVerificationDisabled: request.DisableState,
		CreatedAt:                 provider.currentTime(),
	}
	var err error
	if !request.DisableState {
		session.State, err = provider.randomValue(32)
		if err != nil {
			return gociconnect.Authorization{}, &gociconnect.Error{Kind: gociconnect.ErrInvalidRequest, Op: "generate authorization state", Provider: provider.name, Message: "secure random generation failed"}
		}
	}

	options := make([]oauth2.AuthCodeOption, 0, 1)
	if provider.pkce {
		session.PKCEVerifier, err = provider.randomValue(32)
		if err != nil {
			return gociconnect.Authorization{}, &gociconnect.Error{Kind: gociconnect.ErrInvalidRequest, Op: "generate PKCE verifier", Provider: provider.name, Message: "secure random generation failed"}
		}
		options = append(options, oauth2.S256ChallengeOption(session.PKCEVerifier))
	}

	config := provider.oauthConfig(request.Scopes)
	authorizationURL := config.AuthCodeURL(session.State, options...)
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		return gociconnect.Authorization{}, &gociconnect.Error{Kind: gociconnect.ErrInvalidConfig, Op: "build authorization URL", Provider: provider.name}
	}
	query := parsed.Query()
	if request.DisableState {
		query.Del("state")
	}
	for key, values := range request.Parameters {
		query.Del(key)
		for _, value := range values {
			query.Add(key, value)
		}
	}
	parsed.RawQuery = query.Encode()
	return gociconnect.Authorization{URL: parsed.String(), Session: session}, nil
}

// Complete validates a callback, exchanges its code, and retrieves the provider user.
func (provider *Base) Complete(ctx context.Context, request gociconnect.CompleteRequest) (gociconnect.User, error) {
	if request.Callback.Error != "" {
		return gociconnect.User{}, &gociconnect.CallbackError{
			Code:        request.Callback.Error,
			Description: request.Callback.ErrorDescription,
			URI:         request.Callback.ErrorURI,
		}
	}
	if strings.TrimSpace(request.Callback.Code) == "" {
		return gociconnect.User{}, &gociconnect.Error{Kind: gociconnect.ErrMissingCode, Op: "complete authorization", Provider: provider.name}
	}
	if !request.Session.StateVerificationDisabled {
		if request.Session.State == "" || request.Callback.State == "" || subtle.ConstantTimeCompare([]byte(request.Session.State), []byte(request.Callback.State)) != 1 {
			return gociconnect.User{}, &gociconnect.Error{Kind: gociconnect.ErrStateMismatch, Op: "complete authorization", Provider: provider.name}
		}
	}
	if provider.pkce && request.Session.PKCEVerifier == "" {
		return gociconnect.User{}, &gociconnect.Error{Kind: gociconnect.ErrInvalidCallback, Op: "complete authorization", Provider: provider.name, Message: "PKCE verifier is missing from authorization session"}
	}

	options := make([]oauth2.AuthCodeOption, 0, 1)
	if provider.pkce {
		options = append(options, oauth2.VerifierOption(request.Session.PKCEVerifier))
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, provider.httpClient)
	oauthToken, err := provider.oauthConfig(nil).Exchange(ctx, request.Callback.Code, options...)
	if err != nil {
		return gociconnect.User{}, provider.tokenError(ctx, gociconnect.ErrTokenExchange, "exchange authorization code")
	}
	return provider.resolveUser(ctx, normalizeToken(oauthToken))
}

// User retrieves a provider user using an existing access token.
func (provider *Base) User(ctx context.Context, request gociconnect.UserRequest) (gociconnect.User, error) {
	if strings.TrimSpace(request.AccessToken) == "" {
		return gociconnect.User{}, &gociconnect.Error{Kind: gociconnect.ErrInvalidRequest, Op: "retrieve user", Provider: provider.name, Message: "access token is required"}
	}
	return provider.resolveUser(ctx, gociconnect.Token{AccessToken: request.AccessToken})
}

// Refresh obtains a new access token using a refresh token.
func (provider *Base) Refresh(ctx context.Context, request gociconnect.RefreshRequest) (gociconnect.Token, error) {
	if strings.TrimSpace(request.RefreshToken) == "" {
		return gociconnect.Token{}, &gociconnect.Error{Kind: gociconnect.ErrInvalidRequest, Op: "refresh token", Provider: provider.name, Message: "refresh token is required"}
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, provider.httpClient)
	config := provider.oauthConfig(nil)
	source := config.TokenSource(ctx, &oauth2.Token{RefreshToken: request.RefreshToken})
	token, err := source.Token()
	if err != nil {
		return gociconnect.Token{}, provider.tokenError(ctx, gociconnect.ErrTokenRefresh, "refresh token")
	}
	return normalizeToken(token), nil
}

func (provider *Base) resolveUser(ctx context.Context, token gociconnect.Token) (gociconnect.User, error) {
	fetcher := &apiFetcher{
		provider:        provider.name,
		client:          provider.httpClient,
		accessToken:     token.AccessToken,
		maxResponseSize: provider.maxResponseSize,
	}
	user, err := provider.userResolver.Resolve(ctx, fetcher, token)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, gociconnect.ErrProviderResponse) || errors.Is(err, gociconnect.ErrMalformedResponse) || errors.Is(err, gociconnect.ErrResponseTooLarge) {
			return gociconnect.User{}, err
		}
		return gociconnect.User{}, &gociconnect.Error{Kind: gociconnect.ErrUserRetrieval, Op: "map provider user", Provider: provider.name, Cause: err}
	}
	user.Provider = provider.name
	user.Token = token
	return user, nil
}

func (provider *Base) oauthConfig(scopes []string) *oauth2.Config {
	if len(scopes) == 0 {
		scopes = provider.defaultScopes
	}
	return &oauth2.Config{
		ClientID:     provider.clientID,
		ClientSecret: provider.clientSecret,
		Endpoint:     provider.endpoint,
		RedirectURL:  provider.redirectURL,
		Scopes:       append([]string(nil), scopes...),
	}
}

func (provider *Base) randomValue(size int) (string, error) {
	buffer := make([]byte, size)
	provider.randomMu.Lock()
	defer provider.randomMu.Unlock()
	if _, err := io.ReadFull(provider.random, buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func (provider *Base) currentTime() time.Time {
	provider.nowMu.Lock()
	defer provider.nowMu.Unlock()
	return provider.now()
}

func validAbsoluteURL(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.IsAbs() && parsed.Host != ""
}

func validHTTPURL(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Host != "" && (parsed.Scheme == "https" || parsed.Scheme == "http")
}

func (provider *Base) tokenError(ctx context.Context, kind error, operation string) error {
	if err := ctx.Err(); err != nil {
		return &gociconnect.Error{Kind: kind, Op: operation, Provider: provider.name, Cause: err}
	}
	return &gociconnect.Error{Kind: kind, Op: operation, Provider: provider.name}
}

func normalizeToken(token *oauth2.Token) gociconnect.Token {
	scopes := tokenScopes(token.Extra("scope"))
	return gociconnect.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry,
		Scopes:       scopes,
	}
}

func tokenScopes(value any) []string {
	switch value := value.(type) {
	case string:
		return strings.Fields(value)
	case []string:
		return append([]string(nil), value...)
	case []any:
		scopes := make([]string, 0, len(value))
		for _, scope := range value {
			if text, ok := scope.(string); ok {
				scopes = append(scopes, text)
			}
		}
		return scopes
	default:
		return nil
	}
}

type apiFetcher struct {
	provider        string
	client          *http.Client
	accessToken     string
	maxResponseSize int64
}

func (fetcher *apiFetcher) GetJSON(ctx context.Context, endpoint string, destination any) (json.RawMessage, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, &gociconnect.Error{Kind: gociconnect.ErrInvalidConfig, Op: "create user request", Provider: fetcher.provider, Message: "user endpoint is invalid"}
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+fetcher.accessToken)
	response, err := fetcher.client.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, &gociconnect.Error{Kind: gociconnect.ErrUserRetrieval, Op: "request provider user", Provider: fetcher.provider, Cause: ctxErr}
		}
		return nil, &gociconnect.Error{Kind: gociconnect.ErrUserRetrieval, Op: "request provider user", Provider: fetcher.provider, Cause: err}
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, fetcher.maxResponseSize+1))
	if err != nil {
		return nil, &gociconnect.Error{Kind: gociconnect.ErrUserRetrieval, Op: "read provider user", Provider: fetcher.provider}
	}
	if int64(len(body)) > fetcher.maxResponseSize {
		return nil, &gociconnect.Error{Kind: gociconnect.ErrResponseTooLarge, Op: "read provider user", Provider: fetcher.provider}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, &gociconnect.Error{Kind: gociconnect.ErrProviderResponse, Op: "request provider user", Provider: fetcher.provider, Message: fmt.Sprintf("provider returned HTTP status %d", response.StatusCode)}
	}
	if err := json.Unmarshal(body, destination); err != nil {
		return nil, &gociconnect.Error{Kind: gociconnect.ErrMalformedResponse, Op: "decode provider user", Provider: fetcher.provider}
	}
	return append(json.RawMessage(nil), body...), nil
}
