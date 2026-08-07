package testkit

import (
	"context"
	"fmt"
	"strings"
	"sync"

	gociconnect "github.com/only1enes/goci-connect"
)

// DefaultProviderName is used when ProviderConfig.Name is empty.
const DefaultProviderName = "fake"

// ProviderConfig defines the results and errors returned by a fake Provider.
// NewProvider defensively copies every configured result.
type ProviderConfig struct {
	Name           string
	Authorization  gociconnect.Authorization
	CompletedUser  gociconnect.User
	TokenUser      gociconnect.User
	RefreshedToken gociconnect.Token
	BeginError     error
	CompleteError  error
	UserError      error
	RefreshError   error
}

func (config ProviderConfig) String() string {
	return "{Name:<redacted> Authorization:<redacted> CompletedUser:<redacted> TokenUser:<redacted> RefreshedToken:<redacted> BeginError:<redacted> CompleteError:<redacted> UserError:<redacted> RefreshError:<redacted>}"
}

func (config ProviderConfig) GoString() string { return config.String() }

func (config ProviderConfig) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(config.String()))
}

// CallCounts is an atomic snapshot of calls made to a Provider.
type CallCounts struct {
	Begin    int
	Complete int
	User     int
	Refresh  int
}

// Provider is a configurable, concurrency-safe implementation of
// gociconnect.Provider for application tests. Its zero value is ready for use.
type Provider struct {
	mu sync.RWMutex

	name           string
	authorization  gociconnect.Authorization
	completedUser  gociconnect.User
	tokenUser      gociconnect.User
	refreshedToken gociconnect.Token
	beginError     error
	completeError  error
	userError      error
	refreshError   error

	beginCalls    []gociconnect.BeginRequest
	completeCalls []gociconnect.CompleteRequest
	userCalls     []gociconnect.UserRequest
	refreshCalls  []gociconnect.RefreshRequest
}

var _ gociconnect.Provider = (*Provider)(nil)

// NewProvider creates a fresh fake provider with no recorded calls. An empty
// name uses DefaultProviderName.
func NewProvider(config ProviderConfig) *Provider {
	name := strings.TrimSpace(config.Name)
	if name == "" {
		name = DefaultProviderName
	}
	return &Provider{
		name:           name,
		authorization:  config.Authorization,
		completedUser:  config.CompletedUser.Clone(),
		tokenUser:      config.TokenUser.Clone(),
		refreshedToken: config.RefreshedToken.Clone(),
		beginError:     config.BeginError,
		completeError:  config.CompleteError,
		userError:      config.UserError,
		refreshError:   config.RefreshError,
	}
}

// Name returns the fake provider's immutable canonical name.
func (provider *Provider) Name() string {
	if provider == nil || provider.name == "" {
		return DefaultProviderName
	}
	return provider.name
}

// Begin records a defensive copy of request and returns the configured result.
func (provider *Provider) Begin(_ context.Context, request gociconnect.BeginRequest) (gociconnect.Authorization, error) {
	provider.mu.Lock()
	provider.beginCalls = append(provider.beginCalls, request.Clone())
	result, err := provider.authorization, provider.beginError
	provider.mu.Unlock()
	return result, err
}

// Complete records request and returns a defensive copy of the configured user.
func (provider *Provider) Complete(_ context.Context, request gociconnect.CompleteRequest) (gociconnect.User, error) {
	provider.mu.Lock()
	provider.completeCalls = append(provider.completeCalls, request)
	result, err := provider.completedUser.Clone(), provider.completeError
	provider.mu.Unlock()
	return result, err
}

// User records request and returns a defensive copy of the configured token user.
func (provider *Provider) User(_ context.Context, request gociconnect.UserRequest) (gociconnect.User, error) {
	provider.mu.Lock()
	provider.userCalls = append(provider.userCalls, request)
	result, err := provider.tokenUser.Clone(), provider.userError
	provider.mu.Unlock()
	return result, err
}

// Refresh records request and returns a defensive copy of the configured token.
func (provider *Provider) Refresh(_ context.Context, request gociconnect.RefreshRequest) (gociconnect.Token, error) {
	provider.mu.Lock()
	provider.refreshCalls = append(provider.refreshCalls, request)
	result, err := provider.refreshedToken.Clone(), provider.refreshError
	provider.mu.Unlock()
	return result, err
}

// ConfigureBegin atomically replaces the result and error returned by Begin.
func (provider *Provider) ConfigureBegin(result gociconnect.Authorization, err error) {
	provider.mu.Lock()
	provider.authorization, provider.beginError = result, err
	provider.mu.Unlock()
}

// ConfigureComplete atomically replaces the result and error returned by Complete.
func (provider *Provider) ConfigureComplete(result gociconnect.User, err error) {
	provider.mu.Lock()
	provider.completedUser, provider.completeError = result.Clone(), err
	provider.mu.Unlock()
}

// ConfigureUser atomically replaces the result and error returned by User.
func (provider *Provider) ConfigureUser(result gociconnect.User, err error) {
	provider.mu.Lock()
	provider.tokenUser, provider.userError = result.Clone(), err
	provider.mu.Unlock()
}

// ConfigureRefresh atomically replaces the result and error returned by Refresh.
func (provider *Provider) ConfigureRefresh(result gociconnect.Token, err error) {
	provider.mu.Lock()
	provider.refreshedToken, provider.refreshError = result.Clone(), err
	provider.mu.Unlock()
}

// CallCounts returns an atomic snapshot of per-operation call counts.
func (provider *Provider) CallCounts() CallCounts {
	provider.mu.RLock()
	counts := CallCounts{
		Begin:    len(provider.beginCalls),
		Complete: len(provider.completeCalls),
		User:     len(provider.userCalls),
		Refresh:  len(provider.refreshCalls),
	}
	provider.mu.RUnlock()
	return counts
}

// BeginCallCount returns the number of calls made to Begin.
func (provider *Provider) BeginCallCount() int { return provider.CallCounts().Begin }

// CompleteCallCount returns the number of calls made to Complete.
func (provider *Provider) CompleteCallCount() int { return provider.CallCounts().Complete }

// UserCallCount returns the number of calls made to User.
func (provider *Provider) UserCallCount() int { return provider.CallCounts().User }

// RefreshCallCount returns the number of calls made to Refresh.
func (provider *Provider) RefreshCallCount() int { return provider.CallCounts().Refresh }

// BeginCalls returns defensive copies of all recorded Begin requests.
func (provider *Provider) BeginCalls() []gociconnect.BeginRequest {
	provider.mu.RLock()
	calls := make([]gociconnect.BeginRequest, len(provider.beginCalls))
	for index, call := range provider.beginCalls {
		calls[index] = call.Clone()
	}
	provider.mu.RUnlock()
	return calls
}

// CompleteCalls returns copies of all recorded Complete requests.
func (provider *Provider) CompleteCalls() []gociconnect.CompleteRequest {
	provider.mu.RLock()
	calls := append([]gociconnect.CompleteRequest(nil), provider.completeCalls...)
	provider.mu.RUnlock()
	return calls
}

// UserCalls returns copies of all recorded User requests.
func (provider *Provider) UserCalls() []gociconnect.UserRequest {
	provider.mu.RLock()
	calls := append([]gociconnect.UserRequest(nil), provider.userCalls...)
	provider.mu.RUnlock()
	return calls
}

// RefreshCalls returns copies of all recorded Refresh requests.
func (provider *Provider) RefreshCalls() []gociconnect.RefreshRequest {
	provider.mu.RLock()
	calls := append([]gociconnect.RefreshRequest(nil), provider.refreshCalls...)
	provider.mu.RUnlock()
	return calls
}

// ResetCalls clears all recorded calls without changing configured behavior.
func (provider *Provider) ResetCalls() {
	provider.mu.Lock()
	provider.beginCalls = nil
	provider.completeCalls = nil
	provider.userCalls = nil
	provider.refreshCalls = nil
	provider.mu.Unlock()
}

func (provider *Provider) String() string {
	if provider == nil {
		return "<nil>"
	}
	return "{Name:<redacted> Results:<redacted> Errors:<redacted> Calls:<redacted>}"
}

func (provider *Provider) GoString() string { return provider.String() }

func (provider *Provider) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(provider.String()))
}
