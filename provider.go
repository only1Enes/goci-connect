package gociconnect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// Provider performs stateless, request-scoped social authentication operations.
// Implementations must be safe for concurrent use.
type Provider interface {
	Name() string
	Begin(context.Context, BeginRequest) (Authorization, error)
	Complete(context.Context, CompleteRequest) (User, error)
	User(context.Context, UserRequest) (User, error)
	Refresh(context.Context, RefreshRequest) (Token, error)
}

// BeginRequest contains options for one authorization request.
type BeginRequest struct {
	Scopes       []string
	Parameters   url.Values
	DisableState bool
}

// Authorization contains the provider URL and the session data needed at callback time.
type Authorization struct {
	URL     string
	Session AuthorizationSession
}

// AuthorizationSession contains security-sensitive, request-scoped authorization data.
// Applications must keep it in server-side storage or an authenticated, encrypted client session.
type AuthorizationSession struct {
	State                     string
	PKCEVerifier              string
	StateVerificationDisabled bool
	CreatedAt                 time.Time
}

func (session AuthorizationSession) String() string {
	return fmt.Sprintf("{State:<redacted> PKCEVerifier:<redacted> StateVerificationDisabled:%t CreatedAt:%s}", session.StateVerificationDisabled, session.CreatedAt.Format(time.RFC3339))
}

func (session AuthorizationSession) GoString() string { return session.String() }

// Callback is the normalized OAuth callback query.
type Callback struct {
	Code             string
	State            string
	Error            string
	ErrorDescription string
	ErrorURI         string
}

// CallbackFromValues parses an OAuth callback without coupling the library to an HTTP framework.
func CallbackFromValues(values url.Values) Callback {
	return Callback{
		Code:             values.Get("code"),
		State:            values.Get("state"),
		Error:            values.Get("error"),
		ErrorDescription: values.Get("error_description"),
		ErrorURI:         values.Get("error_uri"),
	}
}

// CompleteRequest contains callback data and the matching authorization session.
type CompleteRequest struct {
	Callback Callback
	Session  AuthorizationSession
}

// UserRequest retrieves a user with an existing access token.
type UserRequest struct {
	AccessToken string
}

// RefreshRequest refreshes an existing OAuth token.
type RefreshRequest struct {
	RefreshToken string
}

// Token is a normalized OAuth token. Metadata contains only non-secret provider fields.
type Token struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	Expiry       time.Time
	Scopes       []string
	Metadata     map[string]any
}

func (token Token) String() string {
	return fmt.Sprintf("{AccessToken:<redacted> RefreshToken:<redacted> TokenType:%q Expiry:%s Scopes:%v Metadata:<omitted>}", token.TokenType, token.Expiry.Format(time.RFC3339), token.Scopes)
}

func (token Token) GoString() string { return token.String() }

// User is a normalized provider user and its associated token.
type User struct {
	Provider  string
	ID        string
	Nickname  string
	Name      string
	Email     string
	AvatarURL string
	Token     Token
	Raw       json.RawMessage
}

func (user User) String() string {
	return fmt.Sprintf("{Provider:%q ID:%q Nickname:%q Name:%q Email:%q AvatarURL:%q Token:%s Raw:<omitted>}", user.Provider, user.ID, user.Nickname, user.Name, user.Email, user.AvatarURL, user.Token.String())
}

func (user User) GoString() string { return user.String() }

func cloneToken(token Token) Token {
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

// CloneUser returns a copy whose mutable fields can be changed independently.
func CloneUser(user User) User {
	user.Token = cloneToken(user.Token)
	user.Raw = append(json.RawMessage(nil), user.Raw...)
	return user
}
