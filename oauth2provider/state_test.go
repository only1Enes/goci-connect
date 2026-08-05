package oauth2provider

import "testing"

func TestValidStateUsesOpaqueEquality(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		received string
		want     bool
	}{
		{name: "equal", expected: "fixed-length-state", received: "fixed-length-state", want: true},
		{name: "same length first byte", expected: "fixed-length-state", received: "xixed-length-state"},
		{name: "same length last byte", expected: "fixed-length-state", received: "fixed-length-statx"},
		{name: "short", expected: "fixed-length-state", received: "fixed"},
		{name: "empty expected", received: "fixed-length-state"},
		{name: "empty received", expected: "fixed-length-state"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validState(test.expected, test.received); got != test.want {
				t.Fatalf("validState() = %t, want %t", got, test.want)
			}
		})
	}
}
