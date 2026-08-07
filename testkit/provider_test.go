package testkit_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"

	gociconnect "github.com/only1enes/goci-connect"
	"github.com/only1enes/goci-connect/testkit"
)

func TestBeginSuccessAndFailure(t *testing.T) {
	want := gociconnect.Authorization{
		URL: "https://provider.example/authorize",
		Session: gociconnect.AuthorizationSession{
			State:        "state",
			PKCEVerifier: "verifier",
		},
	}
	provider := testkit.NewProvider(testkit.ProviderConfig{Authorization: want})
	request := gociconnect.BeginRequest{Scopes: []string{"profile"}}
	got, err := provider.Begin(context.Background(), request)
	if err != nil || got != want {
		t.Fatalf("Begin() = %+v, %v", got, err)
	}

	wantError := errors.New("begin failed")
	provider.ConfigureBegin(gociconnect.Authorization{}, wantError)
	got, err = provider.Begin(context.Background(), gociconnect.BeginRequest{})
	if got != (gociconnect.Authorization{}) || !errors.Is(err, wantError) {
		t.Fatalf("Begin() failure = %+v, %v", got, err)
	}
	if provider.BeginCallCount() != 2 {
		t.Fatalf("BeginCallCount() = %d", provider.BeginCallCount())
	}
}

func TestCompleteSuccessAndFailure(t *testing.T) {
	want := testUser("completed-user", "completed-token")
	provider := testkit.NewProvider(testkit.ProviderConfig{CompletedUser: want})
	request := gociconnect.CompleteRequest{
		Callback: gociconnect.Callback{Code: "code", State: "state"},
		Session:  gociconnect.AuthorizationSession{State: "state"},
	}
	got, err := provider.Complete(context.Background(), request)
	if err != nil || got.ID != want.ID || got.Token.AccessToken != want.Token.AccessToken {
		t.Fatalf("Complete() = %+v, %v", got, err)
	}

	wantError := errors.New("complete failed")
	provider.ConfigureComplete(gociconnect.User{}, wantError)
	got, err = provider.Complete(context.Background(), gociconnect.CompleteRequest{})
	if got.ID != "" || !errors.Is(err, wantError) {
		t.Fatalf("Complete() failure = %+v, %v", got, err)
	}
	if provider.CompleteCallCount() != 2 {
		t.Fatalf("CompleteCallCount() = %d", provider.CompleteCallCount())
	}
}

func TestUserFromTokenSuccessAndFailure(t *testing.T) {
	want := testUser("token-user", "existing-token")
	provider := testkit.NewProvider(testkit.ProviderConfig{TokenUser: want})
	got, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "input-token"})
	if err != nil || got.ID != want.ID || got.Token.AccessToken != want.Token.AccessToken {
		t.Fatalf("User() = %+v, %v", got, err)
	}

	wantError := errors.New("user failed")
	provider.ConfigureUser(gociconnect.User{}, wantError)
	got, err = provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "other-token"})
	if got.ID != "" || !errors.Is(err, wantError) {
		t.Fatalf("User() failure = %+v, %v", got, err)
	}
	if provider.UserCallCount() != 2 {
		t.Fatalf("UserCallCount() = %d", provider.UserCallCount())
	}
}

func TestRefreshSuccessAndFailure(t *testing.T) {
	want := testToken("refreshed-access-token")
	provider := testkit.NewProvider(testkit.ProviderConfig{RefreshedToken: want})
	got, err := provider.Refresh(context.Background(), gociconnect.RefreshRequest{RefreshToken: "old-refresh-token"})
	if err != nil || got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken {
		t.Fatalf("Refresh() = %+v, %v", got, err)
	}

	wantError := errors.New("refresh failed")
	provider.ConfigureRefresh(gociconnect.Token{}, wantError)
	got, err = provider.Refresh(context.Background(), gociconnect.RefreshRequest{RefreshToken: "another-token"})
	if got.AccessToken != "" || !errors.Is(err, wantError) {
		t.Fatalf("Refresh() failure = %+v, %v", got, err)
	}
	if provider.RefreshCallCount() != 2 {
		t.Fatalf("RefreshCallCount() = %d", provider.RefreshCallCount())
	}
}

func TestCallRecordingAndReset(t *testing.T) {
	provider := testkit.NewProvider(testkit.ProviderConfig{Name: "recording"})
	begin := gociconnect.BeginRequest{
		Scopes:     []string{"profile", "email"},
		Parameters: url.Values{"prompt": {"consent"}},
	}
	complete := gociconnect.CompleteRequest{Callback: gociconnect.Callback{Code: "code", State: "state"}}
	user := gociconnect.UserRequest{AccessToken: "access-token"}
	refresh := gociconnect.RefreshRequest{RefreshToken: "refresh-token"}
	_, _ = provider.Begin(context.Background(), begin)
	_, _ = provider.Complete(context.Background(), complete)
	_, _ = provider.User(context.Background(), user)
	_, _ = provider.Refresh(context.Background(), refresh)

	if counts := provider.CallCounts(); counts != (testkit.CallCounts{Begin: 1, Complete: 1, User: 1, Refresh: 1}) {
		t.Fatalf("CallCounts() = %+v", counts)
	}
	if calls := provider.BeginCalls(); len(calls) != 1 || calls[0].Scopes[1] != "email" || calls[0].Parameters.Get("prompt") != "consent" {
		t.Fatalf("BeginCalls() = %+v", calls)
	}
	if calls := provider.CompleteCalls(); len(calls) != 1 || calls[0] != complete {
		t.Fatalf("CompleteCalls() = %+v", calls)
	}
	if calls := provider.UserCalls(); len(calls) != 1 || calls[0] != user {
		t.Fatalf("UserCalls() = %+v", calls)
	}
	if calls := provider.RefreshCalls(); len(calls) != 1 || calls[0] != refresh {
		t.Fatalf("RefreshCalls() = %+v", calls)
	}

	provider.ResetCalls()
	if counts := provider.CallCounts(); counts != (testkit.CallCounts{}) || len(provider.BeginCalls()) != 0 || len(provider.CompleteCalls()) != 0 || len(provider.UserCalls()) != 0 || len(provider.RefreshCalls()) != 0 {
		t.Fatalf("calls after ResetCalls() = %+v", counts)
	}
	configured, err := provider.Begin(context.Background(), gociconnect.BeginRequest{})
	if err != nil || configured != (gociconnect.Authorization{}) {
		t.Fatalf("ResetCalls() changed configured behavior: %+v, %v", configured, err)
	}
}

func TestDefensiveCopies(t *testing.T) {
	configuredComplete := testUser("completed", "complete-token")
	configuredTokenUser := testUser("token-user", "user-token")
	configuredRefresh := testToken("refresh-access-token")
	provider := testkit.NewProvider(testkit.ProviderConfig{
		CompletedUser:  configuredComplete,
		TokenUser:      configuredTokenUser,
		RefreshedToken: configuredRefresh,
	})

	configuredComplete.Raw[0] = 'X'
	configuredComplete.Token.Scopes[0] = "mutated"
	configuredComplete.Token.Metadata["field"][0] = 'X'
	configuredTokenUser.Raw[0] = 'X'
	configuredRefresh.Scopes[0] = "mutated"
	configuredRefresh.Metadata["field"][0] = 'X'

	completed, err := provider.Complete(context.Background(), gociconnect.CompleteRequest{})
	if err != nil {
		t.Fatal(err)
	}
	tokenUser, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "input"})
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := provider.Refresh(context.Background(), gociconnect.RefreshRequest{RefreshToken: "input"})
	if err != nil {
		t.Fatal(err)
	}
	assertUnmutatedUser(t, completed, "completed")
	assertUnmutatedUser(t, tokenUser, "token-user")
	assertUnmutatedToken(t, refreshed)

	completed.Raw[0] = 'Y'
	completed.Token.Scopes[0] = "returned-mutation"
	completed.Token.Metadata["field"][0] = 'Y'
	tokenUser.Raw[0] = 'Y'
	refreshed.Scopes[0] = "returned-mutation"
	refreshed.Metadata["field"][0] = 'Y'
	completedAgain, _ := provider.Complete(context.Background(), gociconnect.CompleteRequest{})
	tokenUserAgain, _ := provider.User(context.Background(), gociconnect.UserRequest{})
	refreshedAgain, _ := provider.Refresh(context.Background(), gociconnect.RefreshRequest{})
	assertUnmutatedUser(t, completedAgain, "completed")
	assertUnmutatedUser(t, tokenUserAgain, "token-user")
	assertUnmutatedToken(t, refreshedAgain)

	request := gociconnect.BeginRequest{
		Scopes:     []string{"one", "two"},
		Parameters: url.Values{"resource": {"original"}},
	}
	_, _ = provider.Begin(context.Background(), request)
	request.Scopes[0] = "input-mutation"
	request.Parameters.Set("resource", "input-mutation")
	calls := provider.BeginCalls()
	if calls[0].Scopes[0] != "one" || calls[0].Parameters.Get("resource") != "original" {
		t.Fatalf("recorded request aliases input: %+v", calls[0])
	}
	calls[0].Scopes[0] = "retrieved-mutation"
	calls[0].Parameters.Set("resource", "retrieved-mutation")
	callsAgain := provider.BeginCalls()
	if callsAgain[0].Scopes[0] != "one" || callsAgain[0].Parameters.Get("resource") != "original" {
		t.Fatalf("recorded request aliases returned calls: %+v", callsAgain[0])
	}
}

func TestConcurrentCallsAndConfiguration(t *testing.T) {
	errorA := errors.New("configured A")
	errorB := errors.New("configured B")
	provider := testkit.NewProvider(testkit.ProviderConfig{
		Authorization:  gociconnect.Authorization{URL: "https://provider.example"},
		CompletedUser:  testUser("complete", "complete-token"),
		TokenUser:      gociconnect.User{ID: "A"},
		RefreshedToken: testToken("refreshed"),
		UserError:      errorA,
	})

	const calls = 200
	errorsChannel := make(chan error, calls*4)
	var wait sync.WaitGroup
	for index := range calls {
		if index%2 == 0 {
			provider.ConfigureUser(gociconnect.User{ID: "A"}, errorA)
		} else {
			provider.ConfigureUser(gociconnect.User{ID: "B"}, errorB)
		}
		wait.Add(4)
		go func() {
			defer wait.Done()
			result, err := provider.Begin(context.Background(), gociconnect.BeginRequest{Scopes: []string{"profile"}})
			if err != nil {
				errorsChannel <- fmt.Errorf("Begin(): %w", err)
			} else if result.URL == "" {
				errorsChannel <- fmt.Errorf("Begin() = %+v", result)
			}
		}()
		go func() {
			defer wait.Done()
			result, err := provider.Complete(context.Background(), gociconnect.CompleteRequest{})
			if err != nil {
				errorsChannel <- fmt.Errorf("Complete(): %w", err)
			} else if result.ID != "complete" {
				errorsChannel <- fmt.Errorf("Complete() = %+v", result)
			}
		}()
		go func() {
			defer wait.Done()
			result, err := provider.User(context.Background(), gociconnect.UserRequest{AccessToken: "token"})
			if (result.ID != "A" || !errors.Is(err, errorA)) && (result.ID != "B" || !errors.Is(err, errorB)) {
				if err != nil {
					errorsChannel <- fmt.Errorf("User() returned a mixed configuration: %+v: %w", result, err)
				} else {
					errorsChannel <- fmt.Errorf("User() returned a mixed configuration without an error: %+v", result)
				}
			}
		}()
		go func() {
			defer wait.Done()
			result, err := provider.Refresh(context.Background(), gociconnect.RefreshRequest{})
			if err != nil {
				errorsChannel <- fmt.Errorf("Refresh(): %w", err)
			} else if result.AccessToken != "refreshed" {
				errorsChannel <- fmt.Errorf("Refresh() = %+v", result)
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
	if counts := provider.CallCounts(); counts != (testkit.CallCounts{Begin: calls, Complete: calls, User: calls, Refresh: calls}) {
		t.Fatalf("CallCounts() = %+v", counts)
	}
}

func TestManagerIntegration(t *testing.T) {
	provider := testkit.NewProvider(testkit.ProviderConfig{
		Name:          "application-fake",
		Authorization: gociconnect.Authorization{URL: "https://fake.example/authorize"},
		CompletedUser: testUser("application-user", "application-token"),
	})
	manager := gociconnect.NewManager()
	if err := manager.Register(provider); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	user, err := applicationLogin(context.Background(), manager, "application-fake")
	if err != nil {
		t.Fatalf("applicationLogin() error = %v", err)
	}
	if user.ID != "application-user" || provider.BeginCallCount() != 1 || provider.CompleteCallCount() != 1 {
		t.Fatalf("user = %+v, calls = %+v", user, provider.CallCounts())
	}
	if provider.BeginCalls()[0].Parameters.Get("prompt") != "login" || provider.CompleteCalls()[0].Callback.Code != "callback-code" {
		t.Fatal("application handler inputs were not recorded")
	}
}

func TestZeroValueAndRedactedFormatting(t *testing.T) {
	var provider testkit.Provider
	if provider.Name() != testkit.DefaultProviderName {
		t.Fatalf("zero-value Name() = %q", provider.Name())
	}
	if _, err := provider.Begin(context.Background(), gociconnect.BeginRequest{}); err != nil || provider.BeginCallCount() != 1 {
		t.Fatalf("zero-value Begin() error = %v, calls = %d", err, provider.BeginCallCount())
	}
	config := testkit.ProviderConfig{
		Name:           "name-secret",
		CompletedUser:  testUser("user-secret", "access-token-secret"),
		RefreshedToken: testToken("refresh-secret"),
		BeginError:     errors.New("error-secret"),
	}
	configured := testkit.NewProvider(config)
	formatted := fmt.Sprintf("%v|%+v|%#v|%v|%+v|%#v", config, config, config, configured, configured, configured)
	for _, secret := range []string{"name-secret", "user-secret", "access-token-secret", "refresh-secret", "error-secret"} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("formatted fake exposes %q: %s", secret, formatted)
		}
	}
}

func applicationLogin(ctx context.Context, manager *gociconnect.Manager, providerName string) (gociconnect.User, error) {
	provider, err := manager.Provider(providerName)
	if err != nil {
		return gociconnect.User{}, err
	}
	authorization, err := provider.Begin(ctx, gociconnect.BeginRequest{Parameters: url.Values{"prompt": {"login"}}})
	if err != nil {
		return gociconnect.User{}, err
	}
	return provider.Complete(ctx, gociconnect.CompleteRequest{
		Callback: gociconnect.Callback{Code: "callback-code", State: authorization.Session.State},
		Session:  authorization.Session,
	})
}

func testUser(id, accessToken string) gociconnect.User {
	return gociconnect.User{
		Provider: "fake",
		ID:       id,
		Token:    testToken(accessToken),
		Raw:      json.RawMessage(`{"field":"value"}`),
	}
}

func testToken(accessToken string) gociconnect.Token {
	return gociconnect.Token{
		AccessToken:  accessToken,
		RefreshToken: "new-refresh-token",
		Scopes:       []string{"profile"},
		Metadata: map[string]json.RawMessage{
			"field": json.RawMessage(`"value"`),
		},
	}
}

func assertUnmutatedUser(t *testing.T, user gociconnect.User, wantID string) {
	t.Helper()
	if user.ID != wantID || string(user.Raw) != `{"field":"value"}` || user.Token.Scopes[0] != "profile" || string(user.Token.Metadata["field"]) != `"value"` {
		t.Fatalf("User() returned mutated data: %+v, raw=%s metadata=%s", user, user.Raw, user.Token.Metadata["field"])
	}
}

func assertUnmutatedToken(t *testing.T, token gociconnect.Token) {
	t.Helper()
	if token.Scopes[0] != "profile" || string(token.Metadata["field"]) != `"value"` {
		t.Fatalf("Refresh() returned mutated data: %+v metadata=%s", token, token.Metadata["field"])
	}
}
