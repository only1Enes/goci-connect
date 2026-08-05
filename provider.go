package gociconnect

import "context"

// Provider performs stateless, request-scoped authentication operations.
// Implementations must be safe for concurrent use.
type Provider interface {
	Name() string
	Begin(context.Context, BeginRequest) (Authorization, error)
	Complete(context.Context, CompleteRequest) (User, error)
	User(context.Context, UserRequest) (User, error)
	Refresh(context.Context, RefreshRequest) (Token, error)
}
