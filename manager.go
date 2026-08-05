package gociconnect

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
)

// Manager is a concurrency-safe registry of configured provider instances.
// Its zero value is ready for use.
type Manager struct {
	mu        sync.RWMutex
	providers map[string]Provider
	aliases   map[string]string
}

// NewManager creates an empty provider manager.
func NewManager() *Manager {
	return &Manager{
		providers: make(map[string]Provider),
		aliases:   make(map[string]string),
	}
}

// Register adds a provider under its canonical name. Existing names and
// aliases are never overwritten.
func (manager *Manager) Register(provider Provider) error {
	if isNilProvider(provider) {
		return NewError(ErrorCodeInvalidConfiguration, "", "register provider", nil)
	}
	name := normalizeRegistryName(provider.Name())
	if name == "" {
		return NewError(ErrorCodeInvalidConfiguration, "", "register provider", nil)
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.initialize()
	if manager.nameExists(name) {
		return NewError(ErrorCodeDuplicateProvider, name, "register provider", nil)
	}
	manager.providers[name] = provider
	return nil
}

// RegisterAlias adds an alternate lookup name for an existing canonical
// provider. Aliases cannot target other aliases.
func (manager *Manager) RegisterAlias(alias, canonicalName string) error {
	alias = normalizeRegistryName(alias)
	canonicalName = normalizeRegistryName(canonicalName)
	if alias == "" || canonicalName == "" {
		return NewError(ErrorCodeInvalidConfiguration, canonicalName, "register provider alias", nil)
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.initialize()
	if manager.nameExists(alias) {
		return NewError(ErrorCodeDuplicateProvider, alias, "register provider alias", nil)
	}
	if _, exists := manager.providers[canonicalName]; !exists {
		return NewError(ErrorCodeProviderNotFound, canonicalName, "register provider alias", nil)
	}
	manager.aliases[alias] = canonicalName
	return nil
}

// Provider retrieves a provider by canonical name or explicit alias.
func (manager *Manager) Provider(name string) (Provider, error) {
	name = normalizeRegistryName(name)
	manager.mu.RLock()
	provider, exists := manager.providers[name]
	if !exists {
		if canonicalName, aliasExists := manager.aliases[name]; aliasExists {
			provider, exists = manager.providers[canonicalName]
		}
	}
	manager.mu.RUnlock()
	if !exists {
		return nil, NewError(ErrorCodeProviderNotFound, name, "retrieve provider", nil)
	}
	return provider, nil
}

// Names returns canonical provider names in lexical order. The returned slice
// is independent of manager state and does not include aliases.
func (manager *Manager) Names() []string {
	manager.mu.RLock()
	names := make([]string, 0, len(manager.providers))
	for name := range manager.providers {
		names = append(names, name)
	}
	manager.mu.RUnlock()
	sort.Strings(names)
	return names
}

func (manager *Manager) String() string {
	if manager == nil {
		return "<nil>"
	}
	return "{Providers:<redacted> Aliases:<redacted>}"
}

func (manager *Manager) GoString() string { return manager.String() }

func (manager *Manager) Format(state fmt.State, _ rune) {
	writeRedacted(state, manager.String())
}

func (manager *Manager) initialize() {
	if manager.providers == nil {
		manager.providers = make(map[string]Provider)
	}
	if manager.aliases == nil {
		manager.aliases = make(map[string]string)
	}
}

func (manager *Manager) nameExists(name string) bool {
	if _, exists := manager.providers[name]; exists {
		return true
	}
	_, exists := manager.aliases[name]
	return exists
}

func normalizeRegistryName(name string) string {
	return strings.TrimSpace(name)
}

func isNilProvider(provider Provider) bool {
	if provider == nil {
		return true
	}
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return value.IsNil()
	default:
		return false
	}
}
