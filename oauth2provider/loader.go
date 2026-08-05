package oauth2provider

import (
	"context"
	"encoding/json"

	gociconnect "github.com/only1enes/goci-connect"
)

// Fetcher performs authenticated, bounded provider API requests. It is scoped
// to one user-loading operation and must not be retained.
type Fetcher interface {
	GetJSON(context.Context, string, any) (json.RawMessage, error)
}

// UserLoader retrieves and maps a provider user. Implementations must be safe
// for concurrent use and must not retain the request-scoped fetcher or token.
type UserLoader interface {
	LoadUser(context.Context, Fetcher, gociconnect.Token) (gociconnect.User, error)
}

// UserLoaderFunc adapts a function to UserLoader.
type UserLoaderFunc func(context.Context, Fetcher, gociconnect.Token) (gociconnect.User, error)

// LoadUser calls the adapted function.
func (loader UserLoaderFunc) LoadUser(ctx context.Context, fetcher Fetcher, token gociconnect.Token) (gociconnect.User, error) {
	return loader(ctx, fetcher, token)
}

// UserMapper maps one raw provider user document to the normalized user model.
// Implementations must be safe for concurrent use and must not retain the input.
type UserMapper interface {
	MapUser(json.RawMessage) (gociconnect.User, error)
}

// UserMapperFunc adapts a function to UserMapper.
type UserMapperFunc func(json.RawMessage) (gociconnect.User, error)

// MapUser calls the adapted function.
func (mapper UserMapperFunc) MapUser(raw json.RawMessage) (gociconnect.User, error) {
	return mapper(raw)
}

type mappedUserLoader struct {
	endpoint string
	mapper   UserMapper
}

func (loader mappedUserLoader) LoadUser(ctx context.Context, fetcher Fetcher, _ gociconnect.Token) (gociconnect.User, error) {
	var document json.RawMessage
	raw, err := fetcher.GetJSON(ctx, loader.endpoint, &document)
	if err != nil {
		return gociconnect.User{}, err
	}
	user, err := loader.mapper.MapUser(raw)
	if err != nil {
		return gociconnect.User{}, gociconnect.NewError(gociconnect.ErrorCodeDecoding, "", "map provider user", nil)
	}
	if user.Raw == nil {
		user.Raw = cloneRaw(raw)
	}
	return user, nil
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	if raw == nil {
		return nil
	}
	clone := make(json.RawMessage, len(raw))
	copy(clone, raw)
	return clone
}
