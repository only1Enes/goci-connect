package github_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gociconnect "github.com/only1enes/goci-connect"
	"github.com/only1enes/goci-connect/providers/github"
)

func TestUserMappingAndPrimaryEmailFallback(t *testing.T) {
	var emailRequests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer github-token" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		switch request.URL.Path {
		case "/user":
			io.WriteString(writer, `{"id":42,"login":"octocat","name":"Mona Lisa","email":"","avatar_url":"https://example.com/avatar.png"}`)
		case "/user/emails":
			emailRequests++
			io.WriteString(writer, `[{"email":"other@example.com","primary":false,"verified":true},{"email":"primary@example.com","primary":true,"verified":true}]`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider, err := github.New(github.Config{
		ClientID: "client", RedirectURL: "https://app.example/callback", APIURL: server.URL, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "github-token"})
	if err != nil {
		t.Fatalf("User() error = %v", err)
	}
	if user.Provider != "github" || user.ID != "42" || user.Nickname != "octocat" || user.Name != "Mona Lisa" || user.Email != "primary@example.com" || user.AvatarURL == "" {
		t.Fatalf("User() = %+v", user)
	}
	if emailRequests != 1 {
		t.Fatalf("email requests = %d", emailRequests)
	}
}

func TestUserDoesNotFetchEmailsWhenProfileHasOne(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/user/emails" {
			t.Fatal("unexpected email fallback request")
		}
		io.WriteString(writer, `{"id":7,"login":"user","email":"profile@example.com"}`)
	}))
	defer server.Close()
	provider, err := github.New(github.Config{ClientID: "client", RedirectURL: "https://app.example/callback", APIURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "token"})
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "profile@example.com" {
		t.Fatalf("Email = %q", user.Email)
	}
}

func TestEmailFallbackPropagatesProviderErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/user" {
			io.WriteString(writer, `{"id":7,"login":"user"}`)
			return
		}
		http.Error(writer, "denied", http.StatusForbidden)
	}))
	defer server.Close()
	provider, err := github.New(github.Config{ClientID: "client", RedirectURL: "https://app.example/callback", APIURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "token"})
	if !errors.Is(err, gociconnect.ErrProviderResponse) {
		t.Fatalf("User() error = %v", err)
	}
}

func TestConfigFormattingRedactsClientSecret(t *testing.T) {
	config := github.Config{ClientID: "client", ClientSecret: "github-client-secret"}
	if strings.Contains(config.String()+config.GoString(), "github-client-secret") {
		t.Fatal("GitHub config formatting exposes client secret")
	}
}
