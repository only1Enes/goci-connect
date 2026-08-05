package gociconnect_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	gociconnect "github.com/only1enes/goci-connect"
)

func TestErrorWrappingAndInspection(t *testing.T) {
	cause := errors.New("transport cause containing access-token-secret")
	operationError := gociconnect.NewError(
		gociconnect.ErrorCodeTransport,
		"github",
		"retrieve user",
		cause,
	)
	wrapped := fmt.Errorf("application boundary: %w", operationError)

	if !errors.Is(wrapped, gociconnect.ErrTransport) {
		t.Fatal("wrapped error does not match ErrTransport")
	}
	if !errors.Is(wrapped, cause) {
		t.Fatal("wrapped error does not preserve its cause")
	}
	var inspected *gociconnect.Error
	if !errors.As(wrapped, &inspected) {
		t.Fatal("wrapped error cannot be inspected as *gociconnect.Error")
	}
	if inspected.Code() != gociconnect.ErrorCodeTransport {
		t.Fatalf("Code() = %q", inspected.Code())
	}
	if inspected.Provider() != "github" || inspected.Operation() != "retrieve user" {
		t.Fatalf("inspection = provider %q, operation %q", inspected.Provider(), inspected.Operation())
	}
	code, ok := gociconnect.ErrorCodeOf(wrapped)
	if !ok || code != gociconnect.ErrorCodeTransport {
		t.Fatalf("ErrorCodeOf() = %q, %t", code, ok)
	}
	if !gociconnect.IsErrorCode(wrapped, gociconnect.ErrorCodeTransport) {
		t.Fatal("IsErrorCode() = false")
	}
}

func TestErrorCategories(t *testing.T) {
	tests := []struct {
		code     gociconnect.ErrorCode
		sentinel error
	}{
		{gociconnect.ErrorCodeInvalidConfiguration, gociconnect.ErrInvalidConfiguration},
		{gociconnect.ErrorCodeInvalidRequest, gociconnect.ErrInvalidRequest},
		{gociconnect.ErrorCodeAuthorizationDenied, gociconnect.ErrAuthorizationDenied},
		{gociconnect.ErrorCodeStateValidation, gociconnect.ErrStateValidation},
		{gociconnect.ErrorCodeTokenExchange, gociconnect.ErrTokenExchange},
		{gociconnect.ErrorCodeTokenRefresh, gociconnect.ErrTokenRefresh},
		{gociconnect.ErrorCodeTransport, gociconnect.ErrTransport},
		{gociconnect.ErrorCodeProviderResponse, gociconnect.ErrProviderResponse},
		{gociconnect.ErrorCodeDecoding, gociconnect.ErrDecoding},
		{gociconnect.ErrorCodeUnsupported, gociconnect.ErrUnsupported},
		{gociconnect.ErrorCodeProviderNotFound, gociconnect.ErrProviderNotFound},
		{gociconnect.ErrorCodeDuplicateProvider, gociconnect.ErrDuplicateProvider},
	}

	for _, test := range tests {
		t.Run(string(test.code), func(t *testing.T) {
			err := gociconnect.NewError(test.code, "provider", "operation", nil)
			if !errors.Is(err, test.sentinel) {
				t.Fatalf("errors.Is(%q) = false", test.code)
			}
			if gociconnect.IsErrorCode(err, gociconnect.ErrorCodeUnknown) {
				t.Fatal("categorized error matched unknown code")
			}
			code, ok := gociconnect.ErrorCodeOf(test.sentinel)
			if !ok || code != test.code {
				t.Fatalf("sentinel ErrorCodeOf() = %q, %t", code, ok)
			}
		})
	}
}

func TestErrorFormattingRedactsInspectionValuesAndCause(t *testing.T) {
	err := gociconnect.NewError(
		gociconnect.ErrorCodeTokenExchange,
		"provider-client-secret",
		"operation-authorization-code",
		errors.New("cause-refresh-token-secret"),
	)
	formatted := fmt.Sprintf("%s|%v|%+v|%#v|%q|%x|%d", err, err, err, err, err, err, err)
	for _, secret := range []string{
		"provider-client-secret",
		"operation-authorization-code",
		"cause-refresh-token-secret",
	} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("formatted error contains %q: %s", secret, formatted)
		}
	}
	if formatted == "" {
		t.Fatal("formatted error is empty")
	}
}

func TestErrorZeroValues(t *testing.T) {
	var nilError *gociconnect.Error
	if nilError.Error() != "<nil>" || nilError.Code() != gociconnect.ErrorCodeUnknown || nilError.Provider() != "" || nilError.Operation() != "" || nilError.Unwrap() != nil {
		t.Fatalf("nil error behavior is inconsistent: %v", nilError)
	}

	zero := gociconnect.NewError(gociconnect.ErrorCode("unrecognized"), "", "", nil)
	if zero.Code() != gociconnect.ErrorCodeUnknown {
		t.Fatalf("invalid code was not normalized: %q", zero.Code())
	}
	if errors.Is(zero, gociconnect.ErrInvalidRequest) {
		t.Fatal("unknown error matched a category")
	}
	if _, ok := gociconnect.ErrorCodeOf(nil); ok {
		t.Fatal("ErrorCodeOf(nil) reported a category")
	}
	if gociconnect.IsErrorCode(nil, gociconnect.ErrorCodeUnknown) {
		t.Fatal("IsErrorCode(nil) = true")
	}
}
