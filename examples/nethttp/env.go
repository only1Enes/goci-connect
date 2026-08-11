package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func loadEnvironmentFile(path string) error {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open environment file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	values, err := parseEnvironment(file)
	if err != nil {
		return fmt.Errorf("parse environment file: %w", err)
	}
	for key, value := range values {
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set environment variable %s: %w", key, err)
		}
	}
	return nil
}

func parseEnvironment(reader io.Reader) (map[string]string, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(reader)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		key, rawValue, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !found || !validEnvironmentKey(key) {
			return nil, fmt.Errorf("line %d has an invalid variable declaration", lineNumber)
		}
		value, err := parseEnvironmentValue(strings.TrimSpace(rawValue))
		if err != nil {
			return nil, fmt.Errorf("line %d for %s: %w", lineNumber, key, err)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read environment file: %w", err)
	}
	return values, nil
}

func parseEnvironmentValue(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	switch value[0] {
	case '"':
		unquoted, err := strconv.Unquote(value)
		if err != nil {
			return "", errors.New("invalid double-quoted value")
		}
		return unquoted, nil
	case '\'':
		if len(value) < 2 || value[len(value)-1] != '\'' {
			return "", errors.New("invalid single-quoted value")
		}
		return value[1 : len(value)-1], nil
	default:
		return value, nil
	}
}

func validEnvironmentKey(key string) bool {
	if key == "" || !validEnvironmentKeyStart(key[0]) {
		return false
	}
	for index := 1; index < len(key); index++ {
		if !validEnvironmentKeyCharacter(key[index]) {
			return false
		}
	}
	return true
}

func validEnvironmentKeyStart(character byte) bool {
	return character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
}

func validEnvironmentKeyCharacter(character byte) bool {
	return validEnvironmentKeyStart(character) || character >= '0' && character <= '9'
}
