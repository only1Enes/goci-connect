// Package testkit provides deterministic providers for application tests.
package testkit

import (
	"context"
	"strings"
	"sync"

	gociconnect "github.com/only1enes/goci-connect"
)

// FakeProviderConfig configures a FakeProvider. Function fields take precedence over static results.
type FakeProviderConfig struct {
	Name          string
	Authorization gociconnect.Authorization
	User          gociconnect.User
	Token         gociconnect.Token
	BeginError    error
	CompleteError error
	UserError     error
	RefreshError  error
	BeginFunc     func(context.Context, gociconnect.BeginRequest) (gociconnect.Authorization, error)
	CompleteFunc  func(context.Context, gociconnect.CompleteRequest) (gociconnect.User, error)
	UserFunc      func(context.Context, gociconnect.UserRequest) (gociconnect.User, error)
	RefreshFunc   func(context.Context, gociconnect.RefreshRequest) (gociconnect.Token, error)
}

// FakeProvider is a concurrency-safe configurable provider that records requests.
type FakeProvider struct {
	config           FakeProviderConfig
	mu               sync.Mutex
	beginRequests    []gociconnect.BeginRequest
	completeRequests []gociconnect.CompleteRequest
	userRequests     []gociconnect.UserRequest
	refreshRequests  []gociconnect.RefreshRequest
}

// NewFakeProvider creates a fake provider with copied static result values.
func NewFakeProvider(config FakeProviderConfig) (*FakeProvider, error) {
	config.Name = strings.ToLower(strings.TrimSpace(config.Name))
	if config.Name == "" {
		return nil, &gociconnect.Error{Kind: gociconnect.ErrInvalidConfig, Op: "create fake provider", Message: "provider name is required"}
	}
	config.User = gociconnect.CloneUser(config.User)
	config.Authorization.Session = cloneSession(config.Authorization.Session)
	config.Token = cloneToken(config.Token)
	return &FakeProvider{config: config}, nil
}

func (provider *FakeProvider) Name() string { return provider.config.Name }

func (provider *FakeProvider) Begin(ctx context.Context, request gociconnect.BeginRequest) (gociconnect.Authorization, error) {
	request = cloneBeginRequest(request)
	provider.mu.Lock()
	provider.beginRequests = append(provider.beginRequests, request)
	provider.mu.Unlock()
	if provider.config.BeginFunc != nil {
		return provider.config.BeginFunc(ctx, request)
	}
	return provider.config.Authorization, provider.config.BeginError
}

func (provider *FakeProvider) Complete(ctx context.Context, request gociconnect.CompleteRequest) (gociconnect.User, error) {
	provider.mu.Lock()
	provider.completeRequests = append(provider.completeRequests, request)
	provider.mu.Unlock()
	if provider.config.CompleteFunc != nil {
		return provider.config.CompleteFunc(ctx, request)
	}
	return gociconnect.CloneUser(provider.config.User), provider.config.CompleteError
}

func (provider *FakeProvider) User(ctx context.Context, request gociconnect.UserRequest) (gociconnect.User, error) {
	provider.mu.Lock()
	provider.userRequests = append(provider.userRequests, request)
	provider.mu.Unlock()
	if provider.config.UserFunc != nil {
		return provider.config.UserFunc(ctx, request)
	}
	return gociconnect.CloneUser(provider.config.User), provider.config.UserError
}

func (provider *FakeProvider) Refresh(ctx context.Context, request gociconnect.RefreshRequest) (gociconnect.Token, error) {
	provider.mu.Lock()
	provider.refreshRequests = append(provider.refreshRequests, request)
	provider.mu.Unlock()
	if provider.config.RefreshFunc != nil {
		return provider.config.RefreshFunc(ctx, request)
	}
	return cloneToken(provider.config.Token), provider.config.RefreshError
}

// BeginRequests returns recorded begin requests as defensive copies.
func (provider *FakeProvider) BeginRequests() []gociconnect.BeginRequest {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	requests := make([]gociconnect.BeginRequest, len(provider.beginRequests))
	for index, request := range provider.beginRequests {
		requests[index] = cloneBeginRequest(request)
	}
	return requests
}

// CompleteRequests returns recorded complete requests as defensive copies.
func (provider *FakeProvider) CompleteRequests() []gociconnect.CompleteRequest {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]gociconnect.CompleteRequest(nil), provider.completeRequests...)
}

// UserRequests returns recorded existing-token requests as defensive copies.
func (provider *FakeProvider) UserRequests() []gociconnect.UserRequest {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]gociconnect.UserRequest(nil), provider.userRequests...)
}

// RefreshRequests returns recorded refresh requests as defensive copies.
func (provider *FakeProvider) RefreshRequests() []gociconnect.RefreshRequest {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]gociconnect.RefreshRequest(nil), provider.refreshRequests...)
}

func cloneBeginRequest(request gociconnect.BeginRequest) gociconnect.BeginRequest {
	request.Scopes = append([]string(nil), request.Scopes...)
	if request.Parameters != nil {
		parameters := make(map[string][]string, len(request.Parameters))
		for key, values := range request.Parameters {
			parameters[key] = append([]string(nil), values...)
		}
		request.Parameters = parameters
	}
	return request
}

func cloneSession(session gociconnect.AuthorizationSession) gociconnect.AuthorizationSession {
	return session
}

func cloneToken(token gociconnect.Token) gociconnect.Token {
	token.Scopes = append([]string(nil), token.Scopes...)
	if token.Metadata != nil {
		metadata := make(map[string]any, len(token.Metadata))
		for key, value := range token.Metadata {
			metadata[key] = value
		}
		token.Metadata = metadata
	}
	return token
}
