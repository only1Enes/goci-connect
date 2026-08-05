package google_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gociconnect "github.com/only1enes/goci-connect"
	"github.com/only1enes/goci-connect/providers/google"
)

func TestUserMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer google-token" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		io.WriteString(writer, `{"sub":"google-123","name":"Example User","email":"user@example.com","picture":"https://example.com/picture.jpg"}`)
	}))
	defer server.Close()
	provider, err := google.New(google.Config{
		ClientID: "client", RedirectURL: "https://app.example/callback", UserInfoURL: server.URL, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	user, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "google-token"})
	if err != nil {
		t.Fatalf("User() error = %v", err)
	}
	if user.Provider != "google" || user.ID != "google-123" || user.Name != "Example User" || user.Email != "user@example.com" || user.AvatarURL == "" {
		t.Fatalf("User() = %+v", user)
	}
}

func TestConfigFormattingRedactsClientSecret(t *testing.T) {
	config := google.Config{ClientID: "client", ClientSecret: "google-client-secret"}
	if strings.Contains(config.String()+config.GoString(), "google-client-secret") {
		t.Fatal("Google config formatting exposes client secret")
	}
}
