package oauth2provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	gociconnect "github.com/only1enes/goci-connect"
)

var errResponseTooLarge = errors.New("response too large")

type boundedTransport struct {
	base  http.RoundTripper
	limit int64
}

func (transport *boundedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > transport.limit {
		_ = response.Body.Close()
		return nil, errResponseTooLarge
	}
	response.Body = &boundedReadCloser{
		body:      response.Body,
		remaining: transport.limit,
	}
	return response, nil
}

type boundedReadCloser struct {
	body      io.ReadCloser
	remaining int64
}

func (reader *boundedReadCloser) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if reader.remaining == 0 {
		var extra [1]byte
		count, err := reader.body.Read(extra[:])
		if count > 0 {
			return 0, errResponseTooLarge
		}
		return 0, err
	}
	if int64(len(buffer)) > reader.remaining+1 {
		buffer = buffer[:reader.remaining+1]
	}
	count, err := reader.body.Read(buffer)
	if int64(count) > reader.remaining {
		allowed := int(reader.remaining)
		reader.remaining = 0
		return allowed, errResponseTooLarge
	}
	reader.remaining -= int64(count)
	return count, err
}

func (reader *boundedReadCloser) Close() error {
	return reader.body.Close()
}

type apiFetcher struct {
	providerName    string
	accessToken     string
	client          *http.Client
	maxResponseSize int64
}

func (fetcher *apiFetcher) GetJSON(ctx context.Context, endpoint string, destination any) (json.RawMessage, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, gociconnect.NewError(gociconnect.ErrorCodeInvalidConfiguration, fetcher.providerName, "create provider user request", nil)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+fetcher.accessToken)

	response, err := fetcher.client.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, gociconnect.NewError(gociconnect.ErrorCodeTransport, fetcher.providerName, "request provider user", ctxErr)
		}
		if errors.Is(err, errResponseTooLarge) {
			return nil, gociconnect.NewError(gociconnect.ErrorCodeResponseTooLarge, fetcher.providerName, "request provider user", nil)
		}
		return nil, gociconnect.NewError(gociconnect.ErrorCodeTransport, fetcher.providerName, "request provider user", nil)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, gociconnect.NewError(gociconnect.ErrorCodeProviderResponse, fetcher.providerName, "request provider user", nil)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, fetcher.maxResponseSize+1))
	if err != nil {
		if errors.Is(err, errResponseTooLarge) {
			return nil, gociconnect.NewError(gociconnect.ErrorCodeResponseTooLarge, fetcher.providerName, "read provider user", nil)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, gociconnect.NewError(gociconnect.ErrorCodeTransport, fetcher.providerName, "read provider user", ctxErr)
		}
		return nil, gociconnect.NewError(gociconnect.ErrorCodeTransport, fetcher.providerName, "read provider user", nil)
	}
	if int64(len(body)) > fetcher.maxResponseSize {
		return nil, gociconnect.NewError(gociconnect.ErrorCodeResponseTooLarge, fetcher.providerName, "read provider user", nil)
	}
	if err := json.Unmarshal(body, destination); err != nil {
		return nil, gociconnect.NewError(gociconnect.ErrorCodeDecoding, fetcher.providerName, "decode provider user", nil)
	}
	return cloneRaw(body), nil
}
