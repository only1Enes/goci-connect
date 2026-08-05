package gociconnect_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	gociconnect "github.com/only1enes/goci-connect"
)

func TestBeginRequestCloneIsIndependent(t *testing.T) {
	original := gociconnect.BeginRequest{
		Scopes:     []string{"profile", "email"},
		Parameters: url.Values{"prompt": {"consent", "login"}},
	}
	clone := original.Clone()

	original.Scopes[0] = "changed-original"
	original.Parameters["prompt"][0] = "changed-original"
	if clone.Scopes[0] != "profile" || clone.Parameters["prompt"][0] != "consent" {
		t.Fatalf("clone changed with original: %+v", clone)
	}

	clone.Scopes[1] = "changed-clone"
	clone.Parameters["prompt"][1] = "changed-clone"
	if original.Scopes[1] != "email" || original.Parameters["prompt"][1] != "login" {
		t.Fatalf("original changed with clone: %+v", original)
	}
}

func TestTokenCloneIsIndependent(t *testing.T) {
	original := gociconnect.Token{
		Scopes: []string{"profile", "email"},
		Metadata: map[string]json.RawMessage{
			"resource": json.RawMessage(`{"id":"one"}`),
		},
	}
	clone := original.Clone()

	original.Scopes[0] = "changed-original"
	original.Metadata["resource"][7] = 'x'
	if clone.Scopes[0] != "profile" || string(clone.Metadata["resource"]) != `{"id":"one"}` {
		t.Fatalf("clone changed with original: %+v", clone)
	}

	clone.Scopes[1] = "changed-clone"
	clone.Metadata["resource"][7] = 'y'
	if original.Scopes[1] != "email" || original.Metadata["resource"][7] != 'x' {
		t.Fatalf("original changed with clone: %+v", original)
	}
}

func TestUserCloneIsIndependent(t *testing.T) {
	original := gociconnect.User{
		Token: gociconnect.Token{
			Scopes: []string{"profile"},
			Metadata: map[string]json.RawMessage{
				"resource": json.RawMessage(`{"id":"one"}`),
			},
		},
		Raw: json.RawMessage(`{"id":"user-1"}`),
	}
	clone := original.Clone()

	original.Token.Scopes[0] = "changed-original"
	original.Token.Metadata["resource"][7] = 'x'
	original.Raw[7] = 'x'
	if clone.Token.Scopes[0] != "profile" || string(clone.Token.Metadata["resource"]) != `{"id":"one"}` || string(clone.Raw) != `{"id":"user-1"}` {
		t.Fatalf("clone changed with original: %+v", clone)
	}

	clone.Token.Scopes[0] = "changed-clone"
	clone.Token.Metadata["resource"][7] = 'y'
	clone.Raw[7] = 'y'
	if original.Token.Scopes[0] != "changed-original" || original.Token.Metadata["resource"][7] != 'x' || original.Raw[7] != 'x' {
		t.Fatalf("original changed with clone: %+v", original)
	}
}

func TestClonePreservesNilCollections(t *testing.T) {
	begin := (gociconnect.BeginRequest{}).Clone()
	if begin.Scopes != nil || begin.Parameters != nil {
		t.Fatalf("zero BeginRequest clone = %+v", begin)
	}
	token := (gociconnect.Token{}).Clone()
	if token.Scopes != nil || token.Metadata != nil {
		t.Fatalf("zero Token clone = %+v", token)
	}
	user := (gociconnect.User{}).Clone()
	if user.Raw != nil || user.Token.Scopes != nil || user.Token.Metadata != nil {
		t.Fatalf("zero User clone = %+v", user)
	}

	emptyBegin := (gociconnect.BeginRequest{Scopes: []string{}, Parameters: url.Values{}}).Clone()
	if emptyBegin.Scopes == nil || emptyBegin.Parameters == nil {
		t.Fatalf("empty BeginRequest clone lost non-nil collections: %+v", emptyBegin)
	}
	emptyToken := (gociconnect.Token{Scopes: []string{}, Metadata: map[string]json.RawMessage{}}).Clone()
	if emptyToken.Scopes == nil || emptyToken.Metadata == nil {
		t.Fatalf("empty Token clone lost non-nil collections: %+v", emptyToken)
	}
	emptyUser := (gociconnect.User{Raw: json.RawMessage{}}).Clone()
	if emptyUser.Raw == nil {
		t.Fatalf("empty User clone lost non-nil raw data: %+v", emptyUser)
	}
}

func TestCallbackFromValues(t *testing.T) {
	values := url.Values{
		"code":              {"authorization-code"},
		"state":             {"callback-state"},
		"error":             {"access_denied"},
		"error_description": {"user declined"},
		"error_uri":         {"https://provider.example/error"},
	}
	callback := gociconnect.CallbackFromValues(values)
	values.Set("code", "changed")

	if callback.Code != "authorization-code" || callback.State != "callback-state" || callback.Error != "access_denied" || callback.ErrorDescription != "user declined" || callback.ErrorURI != "https://provider.example/error" {
		t.Fatalf("CallbackFromValues() = %+v", callback)
	}
	if callback := gociconnect.CallbackFromValues(nil); callback != (gociconnect.Callback{}) {
		t.Fatalf("CallbackFromValues(nil) = %+v", callback)
	}
}

func TestTokenExpiredAt(t *testing.T) {
	now := time.Date(2026, time.August, 5, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		expiry time.Time
		at     time.Time
		want   bool
	}{
		{name: "unknown expiry", at: now, want: false},
		{name: "before expiry", expiry: now.Add(time.Minute), at: now, want: false},
		{name: "at expiry", expiry: now, at: now, want: true},
		{name: "after expiry", expiry: now.Add(-time.Minute), at: now, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := (gociconnect.Token{Expiry: test.expiry}).ExpiredAt(test.at); got != test.want {
				t.Fatalf("ExpiredAt() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestSensitiveModelsRedactFormatting(t *testing.T) {
	state := "state-secret"
	verifier := "pkce-verifier-secret"
	accessToken := "access-token-secret"
	refreshToken := "refresh-token-secret"
	values := []any{
		gociconnect.BeginRequest{Scopes: []string{"scope-secret"}, Parameters: url.Values{"custom": {"parameter-secret"}}},
		gociconnect.Authorization{URL: "https://provider.example/authorize?state=url-state-secret", Session: gociconnect.AuthorizationSession{State: state, PKCEVerifier: verifier}},
		gociconnect.AuthorizationSession{State: state, PKCEVerifier: verifier},
		gociconnect.Callback{Code: "authorization-code-secret", State: state, Error: "callback-error-secret", ErrorDescription: "description-secret", ErrorURI: "https://provider.example/error?secret=uri-secret"},
		gociconnect.CompleteRequest{Callback: gociconnect.Callback{Code: "authorization-code-secret", State: state}, Session: gociconnect.AuthorizationSession{State: state, PKCEVerifier: verifier}},
		gociconnect.UserRequest{AccessToken: accessToken},
		gociconnect.RefreshRequest{RefreshToken: refreshToken},
		gociconnect.Token{AccessToken: accessToken, RefreshToken: refreshToken, TokenType: "token-type-secret", Scopes: []string{"token-scope-secret"}, Metadata: map[string]json.RawMessage{"secret": json.RawMessage(`"metadata-secret"`)}},
		gociconnect.User{Provider: "provider-secret", ID: "id-secret", Nickname: "nickname-secret", Name: "name-secret", Email: "email-secret@example.com", AvatarURL: "https://example.com/avatar-secret", Token: gociconnect.Token{AccessToken: accessToken}, Raw: json.RawMessage(`{"secret":"raw-secret"}`)},
	}
	secrets := []string{
		"scope-secret", "parameter-secret", "url-state-secret", state, verifier,
		"authorization-code-secret", "callback-error-secret", "description-secret", "uri-secret",
		accessToken, refreshToken, "token-type-secret", "token-scope-secret", "metadata-secret",
		"provider-secret", "id-secret", "nickname-secret", "name-secret", "email-secret", "avatar-secret", "raw-secret",
	}

	for _, value := range values {
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x|%d", value, value, value, value, value, value, value)
		for _, secret := range secrets {
			if strings.Contains(formatted, secret) {
				t.Fatalf("formatting %T contains %q: %s", value, secret, formatted)
			}
		}
	}
}
