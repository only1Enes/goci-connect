package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseEnvironment(t *testing.T) {
	values, err := parseEnvironment(strings.NewReader(`
# comment
PLAIN=value
WITH_EQUALS=first=second
export EXPORTED="quoted value"
SINGLE='literal value'
EMPTY=
`))
	if err != nil {
		t.Fatalf("parseEnvironment() error = %v", err)
	}
	want := map[string]string{
		"PLAIN":       "value",
		"WITH_EQUALS": "first=second",
		"EXPORTED":    "quoted value",
		"SINGLE":      "literal value",
		"EMPTY":       "",
	}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("parseEnvironment() = %#v, want %#v", values, want)
	}
}

func TestParseEnvironmentRejectsInvalidDeclarationsWithoutValues(t *testing.T) {
	secret := "must-not-appear"
	_, err := parseEnvironment(strings.NewReader("VALID=value\nINVALID KEY=" + secret + "\n"))
	if err == nil {
		t.Fatal("parseEnvironment() error = nil")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("parseEnvironment() error exposed a value: %v", err)
	}
}

func TestLoadEnvironmentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("GOCI_CONNECT_ENV_FILE_TEST=from-file\nGOCI_CONNECT_ENV_FILE_NEW=loaded\n"), 0o600); err != nil {
		t.Fatalf("write environment file: %v", err)
	}
	t.Setenv("GOCI_CONNECT_ENV_FILE_TEST", "from-process")
	t.Setenv("GOCI_CONNECT_ENV_FILE_NEW", "")
	if err := os.Unsetenv("GOCI_CONNECT_ENV_FILE_NEW"); err != nil {
		t.Fatalf("unset test environment: %v", err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("GOCI_CONNECT_ENV_FILE_NEW") })

	if err := loadEnvironmentFile(path); err != nil {
		t.Fatalf("loadEnvironmentFile() error = %v", err)
	}
	if got := os.Getenv("GOCI_CONNECT_ENV_FILE_TEST"); got != "from-process" {
		t.Fatalf("existing environment value = %q, want %q", got, "from-process")
	}
	if got := os.Getenv("GOCI_CONNECT_ENV_FILE_NEW"); got != "loaded" {
		t.Fatalf("new environment value = %q, want %q", got, "loaded")
	}
}

func TestLoadEnvironmentFileAllowsMissingFile(t *testing.T) {
	if err := loadEnvironmentFile(filepath.Join(t.TempDir(), "missing.env")); err != nil {
		t.Fatalf("loadEnvironmentFile() error = %v", err)
	}
}
