package testkit_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	gociconnect "github.com/only1enes/goci-connect"
	"github.com/only1enes/goci-connect/testkit"
)

func TestFakeProviderStaticBehaviorAndRecording(t *testing.T) {
	provider, err := testkit.NewFakeProvider(testkit.FakeProviderConfig{
		Name:          "Custom",
		Authorization: gociconnect.Authorization{URL: "https://example.com/authorize"},
		User:          gociconnect.User{ID: "user-1", Token: gociconnect.Token{Scopes: []string{"profile"}}},
		Token:         gociconnect.Token{AccessToken: "new-token"},
	})
	if err != nil {
		t.Fatalf("NewFakeProvider() error = %v", err)
	}
	beginRequest := gociconnect.BeginRequest{Scopes: []string{"email"}, Parameters: url.Values{"prompt": {"consent"}}}
	authorization, err := provider.Begin(context.Background(), beginRequest)
	if err != nil || authorization.URL == "" {
		t.Fatalf("Begin() = %+v, %v", authorization, err)
	}
	user, err := provider.Complete(context.Background(), gociconnect.CompleteRequest{Callback: gociconnect.Callback{Code: "code"}})
	if err != nil || user.ID != "user-1" {
		t.Fatalf("Complete() = %+v, %v", user, err)
	}
	if _, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "token"}); err != nil {
		t.Fatalf("User() error = %v", err)
	}
	if token, err := provider.Refresh(context.Background(), gociconnect.RefreshRequest{RefreshToken: "refresh"}); err != nil || token.AccessToken != "new-token" {
		t.Fatalf("Refresh() = %+v, %v", token, err)
	}

	beginRequest.Scopes[0] = "changed"
	beginRequest.Parameters.Set("prompt", "changed")
	recorded := provider.BeginRequests()
	if len(recorded) != 1 || recorded[0].Scopes[0] != "email" || recorded[0].Parameters.Get("prompt") != "consent" {
		t.Fatalf("BeginRequests() = %+v", recorded)
	}
	recorded[0].Scopes[0] = "mutated"
	if provider.BeginRequests()[0].Scopes[0] != "email" {
		t.Fatal("BeginRequests() did not return defensive copies")
	}
	if len(provider.CompleteRequests()) != 1 || len(provider.UserRequests()) != 1 || len(provider.RefreshRequests()) != 1 {
		t.Fatal("fake provider did not record all requests")
	}
}

func TestFakeProviderFunctionsAndErrors(t *testing.T) {
	wantErr := errors.New("configured failure")
	provider, err := testkit.NewFakeProvider(testkit.FakeProviderConfig{
		Name: "fake",
		BeginFunc: func(_ context.Context, request gociconnect.BeginRequest) (gociconnect.Authorization, error) {
			return gociconnect.Authorization{URL: request.Parameters.Get("return")}, wantErr
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := provider.Begin(context.Background(), gociconnect.BeginRequest{Parameters: url.Values{"return": {"value"}}})
	if authorization.URL != "value" || !errors.Is(err, wantErr) {
		t.Fatalf("Begin() = %+v, %v", authorization, err)
	}
}

func TestFakeProviderValidatesName(t *testing.T) {
	_, err := testkit.NewFakeProvider(testkit.FakeProviderConfig{})
	if !errors.Is(err, gociconnect.ErrInvalidConfig) {
		t.Fatalf("NewFakeProvider() error = %v", err)
	}
}
