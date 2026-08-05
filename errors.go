package gociconnect

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidConfig       = errors.New("invalid configuration")
	ErrInvalidRequest      = errors.New("invalid request")
	ErrDuplicateProvider   = errors.New("provider already registered")
	ErrProviderNotFound    = errors.New("provider not found")
	ErrInvalidCallback     = errors.New("invalid OAuth callback")
	ErrAuthorizationDenied = errors.New("authorization denied by provider")
	ErrMissingCode         = errors.New("authorization code is missing")
	ErrStateMismatch       = errors.New("authorization state mismatch")
	ErrTokenExchange       = errors.New("token exchange failed")
	ErrTokenRefresh        = errors.New("token refresh failed")
	ErrUserRetrieval       = errors.New("user retrieval failed")
	ErrProviderResponse    = errors.New("provider returned an error response")
	ErrMalformedResponse   = errors.New("provider returned a malformed response")
	ErrResponseTooLarge    = errors.New("provider response is too large")
)

// Error provides a sanitized, inspectable library error.
type Error struct {
	Kind     error
	Op       string
	Provider string
	Message  string
	Cause    error
}

func (err *Error) Error() string {
	if err == nil {
		return "<nil>"
	}
	message := err.Message
	if message == "" && err.Kind != nil {
		message = err.Kind.Error()
	}
	if err.Provider != "" {
		message = fmt.Sprintf("%s: %s", err.Provider, message)
	}
	if err.Op != "" {
		message = fmt.Sprintf("%s: %s", err.Op, message)
	}
	return message
}

func (err *Error) GoString() string { return err.Error() }

func (err *Error) Unwrap() error {
	if err.Cause != nil {
		return err.Cause
	}
	return err.Kind
}

func (err *Error) Is(target error) bool {
	return errors.Is(err.Kind, target) || errors.Is(err.Cause, target)
}

// CallbackError represents an explicit OAuth error returned to the callback URL.
type CallbackError struct {
	Code        string
	Description string
	URI         string
}

func (err *CallbackError) Error() string {
	return "provider returned an OAuth callback error"
}

func (err *CallbackError) GoString() string { return err.Error() }

func (err *CallbackError) Is(target error) bool {
	return target == ErrAuthorizationDenied || target == ErrInvalidCallback
}
