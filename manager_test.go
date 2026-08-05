package gociconnect_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	gociconnect "github.com/only1enes/goci-connect"
)

type registryProvider struct {
	name string
}

func (provider *registryProvider) Name() string {
	return provider.name
}

func (*registryProvider) Begin(context.Context, gociconnect.BeginRequest) (gociconnect.Authorization, error) {
	return gociconnect.Authorization{}, nil
}

func (*registryProvider) Complete(context.Context, gociconnect.CompleteRequest) (gociconnect.User, error) {
	return gociconnect.User{}, nil
}

func (*registryProvider) User(context.Context, gociconnect.UserRequest) (gociconnect.User, error) {
	return gociconnect.User{}, nil
}

func (*registryProvider) Refresh(context.Context, gociconnect.RefreshRequest) (gociconnect.Token, error) {
	return gociconnect.Token{}, nil
}

func TestManagerRegisterAndLookup(t *testing.T) {
	manager := gociconnect.NewManager()
	provider := &registryProvider{name: "github"}
	if err := manager.Register(provider); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	got, err := manager.Provider("github")
	if err != nil {
		t.Fatalf("Provider() error = %v", err)
	}
	if got != provider {
		t.Fatal("Provider() returned a different provider instance")
	}
}

func TestManagerZeroValueIsUsable(t *testing.T) {
	var manager gociconnect.Manager
	provider := &registryProvider{name: "github"}
	if err := manager.Register(provider); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if got, err := manager.Provider("github"); err != nil || got != provider {
		t.Fatalf("Provider() = %v, %v", got, err)
	}
}

func TestManagerRejectsDuplicateRegistrationWithoutOverwrite(t *testing.T) {
	manager := gociconnect.NewManager()
	original := &registryProvider{name: "github"}
	replacement := &registryProvider{name: "github"}
	if err := manager.Register(original); err != nil {
		t.Fatal(err)
	}
	err := manager.Register(replacement)
	if !errors.Is(err, gociconnect.ErrDuplicateProvider) || !gociconnect.IsErrorCode(err, gociconnect.ErrorCodeDuplicateProvider) {
		t.Fatalf("duplicate Register() error = %v", err)
	}
	if got, lookupErr := manager.Provider("github"); lookupErr != nil || got != original {
		t.Fatalf("duplicate registration replaced provider: %v, %v", got, lookupErr)
	}
}

func TestManagerRejectsNilProvider(t *testing.T) {
	tests := []struct {
		name     string
		provider gociconnect.Provider
	}{
		{name: "nil interface"},
		{name: "typed nil", provider: (*registryProvider)(nil)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := gociconnect.NewManager()
			err := manager.Register(test.provider)
			if !errors.Is(err, gociconnect.ErrInvalidConfiguration) {
				t.Fatalf("Register() error = %v", err)
			}
		})
	}
}

func TestManagerRejectsEmptyProviderName(t *testing.T) {
	for _, name := range []string{"", " \t\r\n "} {
		manager := gociconnect.NewManager()
		err := manager.Register(&registryProvider{name: name})
		if !errors.Is(err, gociconnect.ErrInvalidConfiguration) {
			t.Fatalf("Register(%q) error = %v", name, err)
		}
	}
}

func TestManagerUnknownProvider(t *testing.T) {
	manager := gociconnect.NewManager()
	_, err := manager.Provider("missing")
	if !errors.Is(err, gociconnect.ErrProviderNotFound) {
		t.Fatalf("Provider() error = %v", err)
	}
	if code, ok := gociconnect.ErrorCodeOf(err); !ok || code != gociconnect.ErrorCodeProviderNotFound {
		t.Fatalf("ErrorCodeOf() = %q, %t", code, ok)
	}
	var managerError *gociconnect.Error
	if !errors.As(err, &managerError) || managerError.Provider() != "missing" {
		t.Fatalf("provider error inspection = %#v", err)
	}
}

func TestManagerRegisterAlias(t *testing.T) {
	manager := gociconnect.NewManager()
	provider := &registryProvider{name: "github"}
	if err := manager.Register(provider); err != nil {
		t.Fatal(err)
	}
	if err := manager.RegisterAlias("gh", "github"); err != nil {
		t.Fatalf("RegisterAlias() error = %v", err)
	}
	got, err := manager.Provider("gh")
	if err != nil || got != provider {
		t.Fatalf("Provider(alias) = %v, %v", got, err)
	}
	if names := manager.Names(); !slices.Equal(names, []string{"github"}) {
		t.Fatalf("Names() = %v", names)
	}
}

func TestManagerRejectsInvalidAliases(t *testing.T) {
	manager := gociconnect.NewManager()
	if err := manager.Register(&registryProvider{name: "github"}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		alias     string
		canonical string
		want      error
	}{
		{name: "empty alias", canonical: "github", want: gociconnect.ErrInvalidConfiguration},
		{name: "empty canonical", alias: "gh", want: gociconnect.ErrInvalidConfiguration},
		{name: "unknown canonical", alias: "gh", canonical: "missing", want: gociconnect.ErrProviderNotFound},
		{name: "canonical collision", alias: "github", canonical: "github", want: gociconnect.ErrDuplicateProvider},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := manager.RegisterAlias(test.alias, test.canonical)
			if !errors.Is(err, test.want) {
				t.Fatalf("RegisterAlias() error = %v, want %v", err, test.want)
			}
		})
	}

	if err := manager.RegisterAlias("gh", "github"); err != nil {
		t.Fatal(err)
	}
	if err := manager.RegisterAlias("gh", "github"); !errors.Is(err, gociconnect.ErrDuplicateProvider) {
		t.Fatalf("duplicate alias error = %v", err)
	}
	if err := manager.Register(&registryProvider{name: "gh"}); !errors.Is(err, gociconnect.ErrDuplicateProvider) {
		t.Fatalf("provider-alias collision error = %v", err)
	}
	if err := manager.RegisterAlias("github-short", "gh"); !errors.Is(err, gociconnect.ErrProviderNotFound) {
		t.Fatalf("alias chain error = %v", err)
	}
}

func TestManagerNameNormalizationPreservesCase(t *testing.T) {
	manager := gociconnect.NewManager()
	provider := &registryProvider{name: " GitHub "}
	if err := manager.Register(provider); err != nil {
		t.Fatal(err)
	}
	if got, err := manager.Provider("\tGitHub\n"); err != nil || got != provider {
		t.Fatalf("trimmed Provider() = %v, %v", got, err)
	}
	if _, err := manager.Provider("github"); !errors.Is(err, gociconnect.ErrProviderNotFound) {
		t.Fatalf("case-folded Provider() error = %v", err)
	}
}

func TestManagerNamesAreSortedAndIndependent(t *testing.T) {
	manager := gociconnect.NewManager()
	for _, name := range []string{"zeta", "alpha", "middle"} {
		if err := manager.Register(&registryProvider{name: name}); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"alpha", "middle", "zeta"}
	names := manager.Names()
	if !slices.Equal(names, want) {
		t.Fatalf("Names() = %v, want %v", names, want)
	}
	names[0] = "mutated"
	if got := manager.Names(); !slices.Equal(got, want) {
		t.Fatalf("external mutation changed manager names: %v", got)
	}
}

func TestManagerConcurrentReads(t *testing.T) {
	manager := gociconnect.NewManager()
	provider := &registryProvider{name: "github"}
	if err := manager.Register(provider); err != nil {
		t.Fatal(err)
	}
	if err := manager.RegisterAlias("gh", "github"); err != nil {
		t.Fatal(err)
	}

	const goroutines = 64
	const iterations = 100
	errorsChannel := make(chan error, goroutines)
	var wait sync.WaitGroup
	for range goroutines {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range iterations {
				for _, name := range []string{"github", "gh"} {
					got, err := manager.Provider(name)
					if err != nil || got != provider {
						errorsChannel <- fmt.Errorf("Provider(%q) = %v, %w", name, got, err)
						return
					}
				}
				if names := manager.Names(); len(names) != 1 || names[0] != "github" {
					errorsChannel <- fmt.Errorf("Names() = %v", names)
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}

func TestManagerConcurrentRegistrations(t *testing.T) {
	manager := gociconnect.NewManager()
	const count = 100
	errorsChannel := make(chan error, count)
	var wait sync.WaitGroup
	for index := range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			name := fmt.Sprintf("provider-%03d", index)
			if err := manager.Register(&registryProvider{name: name}); err != nil {
				errorsChannel <- err
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Errorf("Register() error = %v", err)
	}
	if names := manager.Names(); len(names) != count {
		t.Fatalf("len(Names()) = %d, want %d", len(names), count)
	}
}

func TestManagerConcurrentDuplicateRegistrations(t *testing.T) {
	manager := gociconnect.NewManager()
	const count = 64
	var successes atomic.Int64
	var duplicates atomic.Int64
	var unexpected atomic.Int64
	var wait sync.WaitGroup
	for range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			err := manager.Register(&registryProvider{name: "shared"})
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, gociconnect.ErrDuplicateProvider):
				duplicates.Add(1)
			default:
				unexpected.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || duplicates.Load() != count-1 || unexpected.Load() != 0 {
		t.Fatalf("registrations = %d success, %d duplicate, %d unexpected", successes.Load(), duplicates.Load(), unexpected.Load())
	}
}

func TestManagerFormattingDoesNotExposeNames(t *testing.T) {
	manager := gociconnect.NewManager()
	if err := manager.Register(&registryProvider{name: "provider-client-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.RegisterAlias("access-token-secret", "provider-client-secret"); err != nil {
		t.Fatal(err)
	}
	formatted := fmt.Sprintf("%v|%+v|%#v|%x", manager, manager, manager, manager)
	for _, secret := range []string{"provider-client-secret", "access-token-secret"} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("manager formatting contains %q: %s", secret, formatted)
		}
	}
}
