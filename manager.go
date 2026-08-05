package gociconnect

import (
	"sort"
	"strings"
	"sync"
)

// Manager is a concurrency-safe provider registry.
type Manager struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewManager creates an empty provider manager.
func NewManager() *Manager {
	return &Manager{providers: make(map[string]Provider)}
}

// Register adds a provider. Names are trimmed, normalized to lowercase, and unique.
func (manager *Manager) Register(provider Provider) error {
	if provider == nil {
		return &Error{Kind: ErrInvalidConfig, Op: "register provider", Message: "provider is nil"}
	}
	name := normalizeProviderName(provider.Name())
	if name == "" {
		return &Error{Kind: ErrInvalidConfig, Op: "register provider", Message: "provider name is empty"}
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.providers == nil {
		manager.providers = make(map[string]Provider)
	}
	if _, exists := manager.providers[name]; exists {
		return &Error{Kind: ErrDuplicateProvider, Op: "register provider", Provider: name}
	}
	manager.providers[name] = provider
	return nil
}

// Provider returns a registered provider by name.
func (manager *Manager) Provider(name string) (Provider, error) {
	name = normalizeProviderName(name)
	manager.mu.RLock()
	provider, exists := manager.providers[name]
	manager.mu.RUnlock()
	if !exists {
		return nil, &Error{Kind: ErrProviderNotFound, Op: "find provider", Provider: name}
	}
	return provider, nil
}

// Names returns registered provider names in lexical order.
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

func normalizeProviderName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
