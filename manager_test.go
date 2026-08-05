package gociconnect_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	gociconnect "github.com/only1enes/goci-connect"
)

type stubProvider struct{ name string }

func (provider stubProvider) Name() string { return provider.name }
func (stubProvider) Begin(context.Context, gociconnect.BeginRequest) (gociconnect.Authorization, error) {
	return gociconnect.Authorization{}, nil
}
func (stubProvider) Complete(context.Context, gociconnect.CompleteRequest) (gociconnect.User, error) {
	return gociconnect.User{}, nil
}
func (stubProvider) User(context.Context, gociconnect.UserRequest) (gociconnect.User, error) {
	return gociconnect.User{}, nil
}
func (stubProvider) Refresh(context.Context, gociconnect.RefreshRequest) (gociconnect.Token, error) {
	return gociconnect.Token{}, nil
}

func TestManagerRegistrationAndLookup(t *testing.T) {
	manager := gociconnect.NewManager()
	provider := stubProvider{name: "GitHub"}
	if err := manager.Register(provider); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	got, err := manager.Provider(" github ")
	if err != nil {
		t.Fatalf("Provider() error = %v", err)
	}
	if got.Name() != "GitHub" {
		t.Fatalf("Provider().Name() = %q", got.Name())
	}
	if err := manager.Register(provider); !errors.Is(err, gociconnect.ErrDuplicateProvider) {
		t.Fatalf("duplicate Register() error = %v", err)
	}
	if _, err := manager.Provider("missing"); !errors.Is(err, gociconnect.ErrProviderNotFound) {
		t.Fatalf("unknown Provider() error = %v", err)
	}
	if names := manager.Names(); len(names) != 1 || names[0] != "github" {
		t.Fatalf("Names() = %v", names)
	}
}

func TestManagerRejectsInvalidProviders(t *testing.T) {
	manager := gociconnect.NewManager()
	if err := manager.Register(nil); !errors.Is(err, gociconnect.ErrInvalidConfig) {
		t.Fatalf("Register(nil) error = %v", err)
	}
	if err := manager.Register(stubProvider{}); !errors.Is(err, gociconnect.ErrInvalidConfig) {
		t.Fatalf("Register(empty name) error = %v", err)
	}
}

func TestManagerConcurrentAccess(t *testing.T) {
	manager := gociconnect.NewManager()
	const count = 50
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			name := fmt.Sprintf("provider-%d", index)
			if err := manager.Register(stubProvider{name: name}); err != nil {
				t.Errorf("Register(%q) error = %v", name, err)
				return
			}
			if _, err := manager.Provider(name); err != nil {
				t.Errorf("Provider(%q) error = %v", name, err)
			}
			_ = manager.Names()
		}()
	}
	wait.Wait()
	if got := len(manager.Names()); got != count {
		t.Fatalf("len(Names()) = %d, want %d", got, count)
	}
}

func TestCallbackFromValues(t *testing.T) {
	callback := gociconnect.CallbackFromValues(map[string][]string{
		"code":              {"code-value"},
		"state":             {"state-value"},
		"error":             {"access_denied"},
		"error_description": {"declined"},
		"error_uri":         {"https://example.com/error"},
	})
	if callback.Code != "code-value" || callback.State != "state-value" || callback.Error != "access_denied" || callback.ErrorDescription != "declined" || callback.ErrorURI == "" {
		t.Fatalf("CallbackFromValues() = %+v", callback)
	}
}

func TestSensitiveValuesAreRedactedFromFormatting(t *testing.T) {
	values := []any{
		gociconnect.AuthorizationSession{State: "state-secret", PKCEVerifier: "verifier-secret"},
		gociconnect.Token{AccessToken: "access-secret", RefreshToken: "refresh-secret", Metadata: map[string]any{"id_token": "metadata-secret"}},
		gociconnect.User{ID: "user", Token: gociconnect.Token{AccessToken: "nested-access-secret"}, Raw: []byte(`{"token":"raw-secret"}`)},
		&gociconnect.CallbackError{Code: "access_denied", Description: "callback-secret"},
	}
	for _, value := range values {
		formatted := fmt.Sprintf("%v %#v", value, value)
		for _, secret := range []string{"state-secret", "verifier-secret", "access-secret", "refresh-secret", "metadata-secret", "nested-access-secret", "raw-secret", "callback-secret"} {
			if strings.Contains(formatted, secret) {
				t.Fatalf("formatting %T exposes %q: %s", value, secret, formatted)
			}
		}
	}
}
