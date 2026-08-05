# Goci Connect

A framework-agnostic and extensible social authentication provider toolkit for Go.

Goci Connect provides concurrency-safe provider registration, explicit request-scoped OAuth data, secure state and PKCE handling, normalized users and tokens, and reusable foundations for custom providers. It has no router, session, or logging dependency.

## Install

```bash
go get github.com/only1enes/goci-connect
```

## Quick Start

```go
package main

import (
	"context"
	"os"

	gociconnect "github.com/only1enes/goci-connect"
	"github.com/only1enes/goci-connect/providers/github"
)

func authenticate(ctx context.Context, callback gociconnect.Callback) (gociconnect.User, error) {
	manager := gociconnect.NewManager()
	provider, err := github.New(github.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GITHUB_REDIRECT_URL"),
	})
	if err != nil {
		return gociconnect.User{}, err
	}
	if err := manager.Register(provider); err != nil {
		return gociconnect.User{}, err
	}

	provider, err = manager.Provider("github")
	if err != nil {
		return gociconnect.User{}, err
	}
	authorization, err := provider.Begin(ctx, gociconnect.BeginRequest{})
	if err != nil {
		return gociconnect.User{}, err
	}

	// Redirect the browser to authorization.URL. Persist authorization.Session
	// securely, then load it when the provider sends the browser back.
	return provider.Complete(ctx, gociconnect.CompleteRequest{
		Callback: callback,
		Session:  authorization.Session,
	})
}
```

With `net/http`, normalize a callback using its query values:

```go
callback := gociconnect.CallbackFromValues(request.URL.Query())
```

The application owns redirects and session persistence. This keeps the package compatible with `net/http`, Chi, Gin, Echo, Fiber, and other frameworks without adapters.

## Built-in Providers

| Provider | Package | Default scopes |
| --- | --- | --- |
| GitHub | `providers/github` | `read:user`, `user:email` |
| Google | `providers/google` | `openid`, `profile`, `email` |

GitHub retrieves a verified primary email from `/user/emails` when the main user response omits it. Both built-in providers use S256 PKCE.

## Token Operations

Retrieve a user with an existing access token:

```go
user, err := provider.User(ctx, gociconnect.UserRequest{
	AccessToken: accessToken,
})
```

Refresh a token:

```go
token, err := provider.Refresh(ctx, gociconnect.RefreshRequest{
	RefreshToken: refreshToken,
})
```

## Request Options

Scopes and authorization parameters belong to individual requests and never mutate the provider:

```go
authorization, err := provider.Begin(ctx, gociconnect.BeginRequest{
	Scopes: []string{"read:user"},
	Parameters: url.Values{
		"prompt": {"consent"},
	},
})
```

Protocol fields such as `state`, `code_challenge`, `client_id`, and `redirect_uri` are reserved and cannot be overridden through `Parameters`.

## Errors

Errors support `errors.Is` and `errors.As`:

```go
switch {
case errors.Is(err, gociconnect.ErrStateMismatch):
	// Reject the callback.
case errors.Is(err, gociconnect.ErrAuthorizationDenied):
	var callbackError *gociconnect.CallbackError
	if errors.As(err, &callbackError) {
		// Inspect callbackError.Code without logging its full callback data.
	}
case errors.Is(err, gociconnect.ErrProviderResponse):
	// The provider returned a non-2xx user response.
}
```

Token endpoint response bodies and credentials are not included in error strings. Sensitive core values and provider configs also redact secrets from standard debug formatting.

## Security

- State verification is enabled by default and uses constant-time comparison.
- State and PKCE verifiers use `crypto/rand` by default.
- PKCE-enabled providers always use S256 and never fall back to plain.
- Provider API responses are bounded to 1 MiB by default.
- Network calls use request contexts and configurable `*http.Client` values.
- Access tokens are sent in authorization headers, not URL parameters.
- Authorization codes, tokens, client secrets, and PKCE verifiers are omitted from error strings.

`BeginRequest.DisableState` is available only for integrations that cannot support state. It is security-sensitive and does not disable PKCE. Never store `AuthorizationSession` in an unsigned browser cookie. Use server-side storage or an authenticated and encrypted client-side session.

## Extending

For non-OAuth protocols, implement the small `gociconnect.Provider` interface. Implementations must be safe for concurrent use and keep request-specific values in request structs.

For OAuth 2.0 providers, configure `oauth2provider.Base` with endpoints, defaults, and a `UserResolver`. The resolver receives a `Fetcher` that applies bearer authentication, context propagation, status validation, bounded reads, and sanitized JSON errors.

## Testing Applications

The `testkit` package provides a configurable fake provider with static results or function hooks. It records defensive copies of begin, complete, user, and refresh requests.

```go
provider, err := testkit.NewFakeProvider(testkit.FakeProviderConfig{
	Name: "github",
	User: gociconnect.User{ID: "test-user"},
})
```

## Development

```bash
gofmt -w $(find . -name '*.go')
go vet ./...
go test ./...
go test -race ./...
```

Tests use local `httptest` servers and never contact real OAuth providers.
