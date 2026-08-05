package gociconnect

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// BeginRequest contains options for one authorization attempt. Its zero value
// requests provider defaults with state verification enabled.
type BeginRequest struct {
	Scopes       []string
	Parameters   url.Values
	DisableState bool
}

// Clone returns a request whose mutable fields do not alias the receiver.
func (request BeginRequest) Clone() BeginRequest {
	request.Scopes = cloneStrings(request.Scopes)
	request.Parameters = cloneValues(request.Parameters)
	return request
}

func (request BeginRequest) String() string {
	return fmt.Sprintf("{Scopes:<omitted> Parameters:<omitted> DisableState:%t}", request.DisableState)
}

func (request BeginRequest) GoString() string { return request.String() }

func (request BeginRequest) Format(state fmt.State, _ rune) {
	writeRedacted(state, request.String())
}

// Authorization contains the provider URL and callback session returned by Begin.
type Authorization struct {
	URL     string
	Session AuthorizationSession
}

func (authorization Authorization) String() string {
	return fmt.Sprintf("{URL:<redacted> Session:%s}", authorization.Session.String())
}

func (authorization Authorization) GoString() string { return authorization.String() }

func (authorization Authorization) Format(state fmt.State, _ rune) {
	writeRedacted(state, authorization.String())
}

// AuthorizationSession carries request-scoped security values between Begin
// and Complete. Applications must store it in a protected session.
type AuthorizationSession struct {
	State                     string
	PKCEVerifier              string
	StateVerificationDisabled bool
	CreatedAt                 time.Time
}

func (session AuthorizationSession) String() string {
	return fmt.Sprintf("{State:<redacted> PKCEVerifier:<redacted> StateVerificationDisabled:%t CreatedAt:<omitted>}", session.StateVerificationDisabled)
}

func (session AuthorizationSession) GoString() string { return session.String() }

func (session AuthorizationSession) Format(state fmt.State, _ rune) {
	writeRedacted(state, session.String())
}

// Callback contains normalized values supplied by an authentication callback.
type Callback struct {
	Code             string
	State            string
	Error            string
	ErrorDescription string
	ErrorURI         string
}

// CallbackFromValues copies recognized callback parameters from URL values.
func CallbackFromValues(values url.Values) Callback {
	return Callback{
		Code:             values.Get("code"),
		State:            values.Get("state"),
		Error:            values.Get("error"),
		ErrorDescription: values.Get("error_description"),
		ErrorURI:         values.Get("error_uri"),
	}
}

func (callback Callback) String() string {
	return "{Code:<redacted> State:<redacted> Error:<redacted> ErrorDescription:<redacted> ErrorURI:<redacted>}"
}

func (callback Callback) GoString() string { return callback.String() }

func (callback Callback) Format(state fmt.State, _ rune) {
	writeRedacted(state, callback.String())
}

// CompleteRequest pairs callback values with the session created by Begin.
type CompleteRequest struct {
	Callback Callback
	Session  AuthorizationSession
}

func (request CompleteRequest) String() string {
	return fmt.Sprintf("{Callback:%s Session:%s}", request.Callback.String(), request.Session.String())
}

func (request CompleteRequest) GoString() string { return request.String() }

func (request CompleteRequest) Format(state fmt.State, _ rune) {
	writeRedacted(state, request.String())
}

// UserRequest retrieves a provider user with an existing access token.
type UserRequest struct {
	AccessToken string
}

func (request UserRequest) String() string {
	return "{AccessToken:<redacted>}"
}

func (request UserRequest) GoString() string { return request.String() }

func (request UserRequest) Format(state fmt.State, _ rune) {
	writeRedacted(state, request.String())
}

// RefreshRequest requests a new token using an existing refresh token.
type RefreshRequest struct {
	RefreshToken string
}

func (request RefreshRequest) String() string {
	return "{RefreshToken:<redacted>}"
}

func (request RefreshRequest) GoString() string { return request.String() }

func (request RefreshRequest) Format(state fmt.State, _ rune) {
	writeRedacted(state, request.String())
}

// Token contains normalized token data. Metadata values are copied JSON so
// provider-specific non-secret fields can be retained without aliasing.
type Token struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	Expiry       time.Time
	Scopes       []string
	Metadata     map[string]json.RawMessage
}

// Clone returns a token whose mutable fields do not alias the receiver.
func (token Token) Clone() Token {
	token.Scopes = cloneStrings(token.Scopes)
	token.Metadata = cloneRawMap(token.Metadata)
	return token
}

// ExpiredAt reports whether a non-zero expiry is at or before the supplied time.
// A token without an expiry is treated as having no known expiration.
func (token Token) ExpiredAt(at time.Time) bool {
	return !token.Expiry.IsZero() && !token.Expiry.After(at)
}

func (token Token) String() string {
	return "{AccessToken:<redacted> RefreshToken:<redacted> TokenType:<redacted> Expiry:<omitted> Scopes:<omitted> Metadata:<omitted>}"
}

func (token Token) GoString() string { return token.String() }

func (token Token) Format(state fmt.State, _ rune) {
	writeRedacted(state, token.String())
}

// User contains a normalized provider identity, its token, and the original
// provider user document. Call Clone before retaining or mutating shared data.
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

// Clone returns a user whose token and raw provider data do not alias the receiver.
func (user User) Clone() User {
	user.Token = user.Token.Clone()
	user.Raw = cloneRawMessage(user.Raw)
	return user
}

func (user User) String() string {
	return "{Provider:<redacted> ID:<redacted> Nickname:<redacted> Name:<redacted> Email:<redacted> AvatarURL:<redacted> Token:<redacted> Raw:<omitted>}"
}

func (user User) GoString() string { return user.String() }

func (user User) Format(state fmt.State, _ rune) {
	writeRedacted(state, user.String())
}

func writeRedacted(state fmt.State, value string) {
	_, _ = state.Write([]byte(value))
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	clone := make([]string, len(values))
	copy(clone, values)
	return clone
}

func cloneValues(values url.Values) url.Values {
	if values == nil {
		return nil
	}
	clone := make(url.Values, len(values))
	for key, entries := range values {
		clone[key] = cloneStrings(entries)
	}
	return clone
}

func cloneRawMap(values map[string]json.RawMessage) map[string]json.RawMessage {
	if values == nil {
		return nil
	}
	clone := make(map[string]json.RawMessage, len(values))
	for key, value := range values {
		clone[key] = cloneRawMessage(value)
	}
	return clone
}

func cloneRawMessage(value json.RawMessage) json.RawMessage {
	if value == nil {
		return nil
	}
	clone := make(json.RawMessage, len(value))
	copy(clone, value)
	return clone
}
