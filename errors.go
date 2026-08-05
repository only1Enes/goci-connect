package gociconnect

import (
	"errors"
	"fmt"
)

// ErrorCode classifies an authentication failure without exposing sensitive data.
type ErrorCode string

const (
	// ErrorCodeUnknown identifies an unclassified or zero-value package error.
	ErrorCodeUnknown ErrorCode = "unknown"
	// ErrorCodeInvalidConfiguration identifies invalid provider configuration.
	ErrorCodeInvalidConfiguration ErrorCode = "invalid_configuration"
	// ErrorCodeInvalidRequest identifies invalid caller input.
	ErrorCodeInvalidRequest ErrorCode = "invalid_request"
	// ErrorCodeAuthorizationDenied identifies an explicit callback denial.
	ErrorCodeAuthorizationDenied ErrorCode = "authorization_denied"
	// ErrorCodeStateValidation identifies failed callback state validation.
	ErrorCodeStateValidation ErrorCode = "state_validation_failed"
	// ErrorCodeTokenExchange identifies an authorization code exchange failure.
	ErrorCodeTokenExchange ErrorCode = "token_exchange_failed"
	// ErrorCodeTokenRefresh identifies a token refresh failure.
	ErrorCodeTokenRefresh ErrorCode = "token_refresh_failed"
	// ErrorCodeTransport identifies a provider network failure.
	ErrorCodeTransport ErrorCode = "transport_failed"
	// ErrorCodeProviderResponse identifies an unsuccessful provider response.
	ErrorCodeProviderResponse ErrorCode = "provider_response_failed"
	// ErrorCodeDecoding identifies a malformed provider response.
	ErrorCodeDecoding ErrorCode = "response_decoding_failed"
	// ErrorCodeUnsupported identifies an operation unsupported by a provider.
	ErrorCodeUnsupported ErrorCode = "unsupported_operation"
	// ErrorCodeProviderNotFound identifies an unknown provider lookup.
	ErrorCodeProviderNotFound ErrorCode = "provider_not_found"
	// ErrorCodeDuplicateProvider identifies a duplicate name or alias registration.
	ErrorCodeDuplicateProvider ErrorCode = "duplicate_provider"
	// ErrorCodeResponseTooLarge identifies a provider response over the configured limit.
	ErrorCodeResponseTooLarge ErrorCode = "response_too_large"
)

var (
	// ErrInvalidConfiguration matches invalid provider configuration errors.
	ErrInvalidConfiguration = &categoryError{code: ErrorCodeInvalidConfiguration}
	// ErrInvalidRequest matches invalid authentication request errors.
	ErrInvalidRequest = &categoryError{code: ErrorCodeInvalidRequest}
	// ErrAuthorizationDenied matches explicit provider callback denials.
	ErrAuthorizationDenied = &categoryError{code: ErrorCodeAuthorizationDenied}
	// ErrStateValidation matches callback state validation errors.
	ErrStateValidation = &categoryError{code: ErrorCodeStateValidation}
	// ErrTokenExchange matches authorization code exchange errors.
	ErrTokenExchange = &categoryError{code: ErrorCodeTokenExchange}
	// ErrTokenRefresh matches refresh token exchange errors.
	ErrTokenRefresh = &categoryError{code: ErrorCodeTokenRefresh}
	// ErrTransport matches failures communicating with a provider.
	ErrTransport = &categoryError{code: ErrorCodeTransport}
	// ErrProviderResponse matches unsuccessful provider responses.
	ErrProviderResponse = &categoryError{code: ErrorCodeProviderResponse}
	// ErrDecoding matches malformed provider response errors.
	ErrDecoding = &categoryError{code: ErrorCodeDecoding}
	// ErrUnsupported matches operations unsupported by a provider.
	ErrUnsupported = &categoryError{code: ErrorCodeUnsupported}
	// ErrProviderNotFound matches unknown provider lookup errors.
	ErrProviderNotFound = &categoryError{code: ErrorCodeProviderNotFound}
	// ErrDuplicateProvider matches duplicate name or alias registration errors.
	ErrDuplicateProvider = &categoryError{code: ErrorCodeDuplicateProvider}
	// ErrResponseTooLarge matches provider responses over the configured limit.
	ErrResponseTooLarge = &categoryError{code: ErrorCodeResponseTooLarge}
)

// Error is a sanitized, inspectable provider operation error. Its cause is
// available through errors.Unwrap but is never included in formatted output.
type Error struct {
	code      ErrorCode
	provider  string
	operation string
	cause     error
}

// NewError creates a package error. Provider and operation are retained for
// inspection but deliberately omitted from Error output.
func NewError(code ErrorCode, provider, operation string, cause error) *Error {
	if !validErrorCode(code) {
		code = ErrorCodeUnknown
	}
	return &Error{code: code, provider: provider, operation: operation, cause: cause}
}

func (err *Error) Error() string {
	if err == nil {
		return "<nil>"
	}
	return errorMessage(err.code)
}

func (err *Error) GoString() string { return err.Error() }

func (err Error) Format(state fmt.State, _ rune) {
	writeRedacted(state, errorMessage(err.code))
}

// Unwrap returns the underlying cause, when one was supplied.
func (err *Error) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

// Is supports category checks with errors.Is.
func (err *Error) Is(target error) bool {
	if err == nil {
		return false
	}
	category, ok := target.(*categoryError)
	return ok && err.code != ErrorCodeUnknown && err.code == category.code
}

// Code returns the stable category code.
func (err *Error) Code() ErrorCode {
	if err == nil {
		return ErrorCodeUnknown
	}
	return err.code
}

// Provider returns the canonical provider name recorded for inspection.
func (err *Error) Provider() string {
	if err == nil {
		return ""
	}
	return err.provider
}

// Operation returns the non-sensitive operation label recorded for inspection.
func (err *Error) Operation() string {
	if err == nil {
		return ""
	}
	return err.operation
}

// ErrorCodeOf returns the first Goci Connect error category in an error chain.
func ErrorCodeOf(err error) (ErrorCode, bool) {
	var packageError *Error
	if errors.As(err, &packageError) {
		return packageError.Code(), true
	}
	var category *categoryError
	if errors.As(err, &category) {
		return category.code, true
	}
	return ErrorCodeUnknown, false
}

// IsErrorCode reports whether an error chain contains the supplied category.
func IsErrorCode(err error, code ErrorCode) bool {
	found, ok := ErrorCodeOf(err)
	return ok && found == code
}

type categoryError struct {
	code ErrorCode
}

func (err *categoryError) Error() string { return errorMessage(err.code) }

func (err *categoryError) GoString() string { return err.Error() }

func (err categoryError) Format(state fmt.State, _ rune) {
	writeRedacted(state, err.Error())
}

func validErrorCode(code ErrorCode) bool {
	switch code {
	case ErrorCodeUnknown,
		ErrorCodeInvalidConfiguration,
		ErrorCodeInvalidRequest,
		ErrorCodeAuthorizationDenied,
		ErrorCodeStateValidation,
		ErrorCodeTokenExchange,
		ErrorCodeTokenRefresh,
		ErrorCodeTransport,
		ErrorCodeProviderResponse,
		ErrorCodeDecoding,
		ErrorCodeUnsupported,
		ErrorCodeProviderNotFound,
		ErrorCodeDuplicateProvider,
		ErrorCodeResponseTooLarge:
		return true
	default:
		return false
	}
}

func errorMessage(code ErrorCode) string {
	switch code {
	case ErrorCodeInvalidConfiguration:
		return "invalid provider configuration"
	case ErrorCodeInvalidRequest:
		return "invalid authentication request"
	case ErrorCodeAuthorizationDenied:
		return "authorization denied by provider"
	case ErrorCodeStateValidation:
		return "authorization state validation failed"
	case ErrorCodeTokenExchange:
		return "token exchange failed"
	case ErrorCodeTokenRefresh:
		return "token refresh failed"
	case ErrorCodeTransport:
		return "provider transport failed"
	case ErrorCodeProviderResponse:
		return "provider returned an unsuccessful response"
	case ErrorCodeDecoding:
		return "provider response decoding failed"
	case ErrorCodeUnsupported:
		return "provider does not support this operation"
	case ErrorCodeProviderNotFound:
		return "provider not found"
	case ErrorCodeDuplicateProvider:
		return "provider name is already registered"
	case ErrorCodeResponseTooLarge:
		return "provider response exceeds the configured limit"
	default:
		return "authentication operation failed"
	}
}
