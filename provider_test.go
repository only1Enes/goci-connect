package gociconnect_test

import (
	"context"
	"errors"
	"testing"

	gociconnect "github.com/only1enes/goci-connect"
)

type contractProvider struct{}

func (contractProvider) Name() string {
	return "contract"
}

func (contractProvider) Begin(context.Context, gociconnect.BeginRequest) (gociconnect.Authorization, error) {
	return gociconnect.Authorization{}, nil
}

func (contractProvider) Complete(context.Context, gociconnect.CompleteRequest) (gociconnect.User, error) {
	return gociconnect.User{}, nil
}

func (contractProvider) User(context.Context, gociconnect.UserRequest) (gociconnect.User, error) {
	return gociconnect.User{}, nil
}

func (contractProvider) Refresh(context.Context, gociconnect.RefreshRequest) (gociconnect.Token, error) {
	return gociconnect.Token{}, gociconnect.NewError(gociconnect.ErrorCodeUnsupported, "contract", "refresh token", nil)
}

func TestProviderContractAndZeroValueRequests(t *testing.T) {
	var provider gociconnect.Provider = contractProvider{}
	if provider.Name() != "contract" {
		t.Fatalf("Name() = %q", provider.Name())
	}
	if _, err := provider.Begin(context.Background(), gociconnect.BeginRequest{}); err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if _, err := provider.Complete(context.Background(), gociconnect.CompleteRequest{}); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if _, err := provider.User(context.Background(), gociconnect.UserRequest{}); err != nil {
		t.Fatalf("User() error = %v", err)
	}
	if _, err := provider.Refresh(context.Background(), gociconnect.RefreshRequest{}); !errors.Is(err, gociconnect.ErrUnsupported) {
		t.Fatalf("Refresh() error = %v", err)
	}
}
