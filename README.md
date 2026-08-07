# Goci Connect

[![CI](https://github.com/only1enes/goci-connect/actions/workflows/ci.yml/badge.svg)](https://github.com/only1enes/goci-connect/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Goci Connect is a framework-agnostic and extensible social authentication provider toolkit for Go.

It provides a small, concurrency-safe API for OAuth 2.0 authorization, callback completion, token refresh, and user retrieval without hidden session storage or framework coupling.

## Features

- Stateless, request-scoped authentication operations
- Concurrency-safe provider manager with explicit aliases
- Secure state generation and constant-time validation by default
- PKCE S256 for every built-in provider
- Normalized users and tokens with defensively copied raw data
- Typed, inspectable, and sanitized errors
- Bounded, context-aware provider HTTP requests
- Reusable `oauth2provider` package for third-party integrations
- Concurrency-safe fake provider for application tests
- Complete standard-library `net/http` example

## Built-in providers

| Provider | Package             | Default scopes                   | PKCE | Refresh |
| -------- | ------------------- | -------------------------------- | ---- | ------- |
| GitHub   | `providers/github`  | None; public profile fields only | S256 | No      |
| Google   | `providers/google`  | `openid profile email`           | S256 | Yes     |
| Discord  | `providers/discord` | `identify email`                 | S256 | Yes     |
| GitLab   | `providers/gitlab`  | `read_user`                      | S256 | Yes     |

GitHub can request `/user/emails` when the returned profile has no email and the granted scopes permit it. GitLab supports GitLab.com by default and HTTPS GitLab Self-Managed base URLs through `gitlab.Config.BaseURL`.

## Installation

```sh
go get github.com/only1enes/goci-connect@latest
```

Import the root package with its Go package name:

```go
import gociconnect "github.com/only1enes/goci-connect"
```

## Quick start

The application owns session persistence. Store the complete `AuthorizationSession` in protected server-side storage and associate it with a cryptographically random opaque session identifier.

```go
package auth

import (
	"context"
	"net/url"
	"os"

	gociconnect "github.com/only1enes/goci-connect"
	githubprovider "github.com/only1enes/goci-connect/providers/github"
)

type SessionStore interface {
	Save(context.Context, string, string, gociconnect.AuthorizationSession) error
	Consume(context.Context, string, string) (gociconnect.AuthorizationSession, error)
}

type Service struct {
	providers *gociconnect.Manager
	sessions  SessionStore
}

func NewService(sessions SessionStore) (*Service, error) {
	provider, err := githubprovider.New(githubprovider.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GITHUB_REDIRECT_URL"),
	})
	if err != nil {
		return nil, err
	}

	manager := gociconnect.NewManager()
	if err := manager.Register(provider); err != nil {
		return nil, err
	}
	return &Service{providers: manager, sessions: sessions}, nil
}

func (service *Service) Begin(ctx context.Context, sessionID string) (string, error) {
	provider, err := service.providers.Provider("github")
	if err != nil {
		return "", err
	}
	authorization, err := provider.Begin(ctx, gociconnect.BeginRequest{})
	if err != nil {
		return "", err
	}
	if err := service.sessions.Save(ctx, sessionID, provider.Name(), authorization.Session); err != nil {
		return "", err
	}
	return authorization.URL, nil
}

func (service *Service) Complete(
	ctx context.Context,
	sessionID string,
	callbackValues url.Values,
) (gociconnect.User, error) {
	provider, err := service.providers.Provider("github")
	if err != nil {
		return gociconnect.User{}, err
	}
	session, err := service.sessions.Consume(ctx, sessionID, provider.Name())
	if err != nil {
		return gociconnect.User{}, err
	}
	return provider.Complete(ctx, gociconnect.CompleteRequest{
		Callback: gociconnect.CallbackFromValues(callbackValues),
		Session:  session,
	})
}
```

Redirect the browser to the URL returned by `Begin`. On the callback, pass the provider query values and atomically consume the stored session. Session records should expire quickly and must not be reusable.

## Provider registration

Construct providers once, then register their configured instances with a manager:

```go
manager := gociconnect.NewManager()
for _, provider := range []gociconnect.Provider{
	githubProvider,
	googleProvider,
	discordProvider,
	gitlabProvider,
} {
	if err := manager.Register(provider); err != nil {
		return err
	}
}

if err := manager.RegisterAlias("company-gitlab", "gitlab"); err != nil {
	return err
}
```

Surrounding whitespace is trimmed while names remain case-sensitive. Duplicate registrations are rejected, and `manager.Names()` returns sorted canonical names without aliases.

## Authorization flow

`Begin` returns both the redirect URL and the security values required by `Complete`:

```go
authorization, err := provider.Begin(ctx, gociconnect.BeginRequest{})
if err != nil {
	return err
}

// Persist authorization.Session in protected storage before redirecting.
redirectURL := authorization.URL
```

Do not store `authorization.Session` in an unsigned or unencrypted browser cookie. It contains the state value and, when supported, the PKCE verifier.

Complete a callback using the same session:

```go
user, err := provider.Complete(ctx, gociconnect.CompleteRequest{
	Callback: gociconnect.CallbackFromValues(request.URL.Query()),
	Session:  storedSession,
})
```

`Complete` validates provider denial, authorization code presence, state, and PKCE requirements before exchanging the code and loading the user.

## Existing tokens and refresh

Retrieve a user with an existing access token:

```go
user, err := provider.User(ctx, gociconnect.UserRequest{
	AccessToken: accessToken,
})
```

Refresh a token when the provider declares refresh support:

```go
token, err := provider.Refresh(ctx, gociconnect.RefreshRequest{
	RefreshToken: refreshToken,
})
if errors.Is(err, gociconnect.ErrUnsupported) {
	// GitHub OAuth Apps do not use this refresh path.
}
```

Refresh results contain normalized token fields only. Persist tokens as secrets and never send them to browser-visible output or application logs.

## Scopes and authorization parameters

A non-empty per-request scope list replaces the provider defaults for that authorization attempt:

```go
authorization, err := provider.Begin(ctx, gociconnect.BeginRequest{
	Scopes: []string{"read:user", "user:email"},
})
```

To extend defaults, include the complete desired list. You can also change a built-in provider's defaults through its `Config.Scopes` field.

Provider-specific authorization parameters are explicit and request-scoped:

```go
authorization, err := googleProvider.Begin(ctx, gociconnect.BeginRequest{
	Parameters: url.Values{
		"access_type": {"offline"},
		"prompt":      {"consent"},
	},
})
```

Google also accepts reusable defaults through `google.Config.AuthorizationParameters`. Goci Connect rejects parameters that could override protocol-critical values, including the client ID, redirect URI, response type, scope, state, and PKCE fields.

## State and PKCE

State verification is enabled by default. `Begin` generates a cryptographically random value, and `Complete` validates it using a constant-time comparison.

State can be disabled only for an individual request:

```go
authorization, err := provider.Begin(ctx, gociconnect.BeginRequest{
	DisableState: true,
})
```

Disabling state removes CSRF protection from the OAuth callback. Use it only when another correctly implemented, application-specific mechanism provides equivalent request binding. The returned session records that verification was disabled; do not alter that field. Disabling state does not disable PKCE.

Every built-in provider enables PKCE S256. `Begin` returns the verifier only inside `AuthorizationSession`, and `Complete` sends it during code exchange. Plain PKCE is never used.

## Normalized users

`User` exposes a stable set of fields:

| Field       | Meaning                                                                         |
| ----------- | ------------------------------------------------------------------------------- |
| `Provider`  | Canonical provider name                                                         |
| `ID`        | Provider-specific user identifier normalized as a string                        |
| `Nickname`  | Username or login when reliably available                                       |
| `Name`      | Display name                                                                    |
| `Email`     | Email when supplied and usable                                                  |
| `AvatarURL` | Provider avatar URL                                                             |
| `Token`     | Normalized access token, refresh token, type, expiry, scopes, and safe metadata |
| `Raw`       | Defensive copy of the original provider user JSON                               |

Optional provider fields may be empty. Call `User.Clone` or `Token.Clone` before retaining and mutating values shared across goroutines.

## Typed errors

Errors are sanitized for formatting and support both category matching and structured inspection:

```go
func handleAuthenticationError(err error) {
	switch {
	case errors.Is(err, gociconnect.ErrAuthorizationDenied):
		log.Print("authorization was declined")
	case errors.Is(err, gociconnect.ErrStateValidation):
		log.Print("authorization session was invalid")
	case errors.Is(err, gociconnect.ErrTransport):
		log.Print("provider was temporarily unavailable")
	}

	var authError *gociconnect.Error
	if errors.As(err, &authError) {
		log.Printf(
			"authentication failed provider=%q operation=%q category=%q",
			authError.Provider(),
			authError.Operation(),
			authError.Code(),
		)
	}
}
```

Other categories distinguish invalid configuration, invalid requests, token exchange, refresh, provider responses, decoding, unsupported operations, unknown providers, duplicates, and oversized responses. Error strings deliberately omit client secrets, codes, tokens, state values, verifiers, and provider response details.

## Testing with a fake provider

The `testkit` package provides a configurable fake with defensive call recording:

```go
fake := testkit.NewProvider(testkit.ProviderConfig{
	Name: "example",
	Authorization: gociconnect.Authorization{
		URL: "https://provider.test/authorize",
		Session: gociconnect.AuthorizationSession{
			State: "test-state",
		},
	},
	CompletedUser: gociconnect.User{
		Provider: "example",
		ID:       "user-123",
		Email:    "person@example.test",
	},
})

manager := gociconnect.NewManager()
if err := manager.Register(fake); err != nil {
	t.Fatal(err)
}

if _, err := fake.Complete(context.Background(), gociconnect.CompleteRequest{}); err != nil {
	t.Fatal(err)
}
if got := fake.CompleteCallCount(); got != 1 {
	t.Fatalf("Complete call count = %d, want 1", got)
}
```

Each fake is independent and safe for concurrent tests. Configure per-operation results or errors, inspect recorded requests, and use `ResetCalls` without changing configured behavior.

## Custom OAuth providers

Use `oauth2provider` to share the same state, PKCE, exchange, refresh, HTTP, and error behavior as the built-ins:

```go
type acmeUser struct {
	ID     string `json:"id"`
	Handle string `json:"handle"`
	Name   string `json:"name"`
	Email  string `json:"email"`
}

func newAcmeProvider(clientID, clientSecret, redirectURL string) (*oauth2provider.Provider, error) {
	mapper := oauth2provider.UserMapperFunc(func(raw json.RawMessage) (gociconnect.User, error) {
		var source acmeUser
		if err := json.Unmarshal(raw, &source); err != nil || source.ID == "" {
			return gociconnect.User{}, gociconnect.NewError(
				gociconnect.ErrorCodeDecoding,
				"acme",
				"map Acme user",
				nil,
			)
		}
		return gociconnect.User{
			ID:       source.ID,
			Nickname: source.Handle,
			Name:     source.Name,
			Email:    source.Email,
		}, nil
	})

	return oauth2provider.New(oauth2provider.Config{
		Name:         "acme",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://auth.acme.test/oauth/authorize",
			TokenURL: "https://auth.acme.test/oauth/token",
		},
		DefaultScopes: []string{"profile"},
		Capabilities: oauth2provider.Capabilities{
			PKCE:         true,
			TokenRefresh: true,
		},
		HTTPClient:   &http.Client{Timeout: 10 * time.Second},
		UserEndpoint: "https://api.acme.test/v1/me",
		UserMapper:   mapper,
	})
}
```

Use `UserLoader` instead of `UserMapper` when a provider requires multiple authenticated requests or conditional profile loading. Custom mappers and loaders must be concurrency-safe and must not retain request-scoped inputs.

## `net/http` example

[`examples/nethttp`](examples/nethttp) is a complete standard-library application with GitHub and Google configuration, opaque cookies, server-side authorization sessions, expiry, one-time callback consumption, secure response headers, and graceful shutdown.

The example's in-memory session store is intentionally local-only. Production deployments need durable or distributed protected storage appropriate to their architecture.

## Concurrency

`Manager`, built-in providers, `oauth2provider.Provider`, and `testkit.Provider` are safe for concurrent use. Provider configuration is copied and immutable after construction. Per-request scopes, parameters, callback values, state, and PKCE data are passed explicitly and never stored as mutable provider state.

Applications remain responsible for concurrency-safe session and token storage. A custom `Provider`, `UserMapper`, or `UserLoader` must also be safe for concurrent use.

## Security guidance

- Keep client secrets, access tokens, refresh tokens, codes, state, and PKCE verifiers out of logs and browser output.
- Store authorization sessions server-side, or use authenticated and encrypted client-side storage.
- Bind sessions to the selected provider, expire them quickly, and consume them exactly once.
- Put only a random opaque session identifier in an `HttpOnly`, `SameSite` cookie; use `Secure` with HTTPS.
- Keep state verification enabled and preserve PKCE session data exactly as returned.
- Use HTTPS provider endpoints, explicit HTTP client timeouts, and request contexts with deadlines.
- Keep Go and dependencies patched, and run `govulncheck ./...` regularly.
- Treat `User.Raw` and token metadata as provider-controlled input.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Go version policy

The module requires Go 1.23 or newer. CI tests the minimum supported language version and the two Go releases currently supported by the Go project. Security-sensitive deployments should use the latest patch release of a supported Go version.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request. Provider requests should include links to the provider's official OAuth and user API documentation.

Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not through a public issue.

## License

Goci Connect is available under the [MIT License](LICENSE).
