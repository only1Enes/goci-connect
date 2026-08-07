package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	gociconnect "github.com/only1enes/goci-connect"
	githubprovider "github.com/only1enes/goci-connect/providers/github"
	googleprovider "github.com/only1enes/goci-connect/providers/google"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := loadEnvironmentFile(".env"); err != nil {
		return err
	}
	logger := log.New(os.Stdout, "nethttp-example: ", log.LstdFlags)
	manager, err := managerFromEnvironment(os.Getenv)
	if err != nil {
		return err
	}
	secureCookie, err := booleanEnvironment(os.Getenv, "GOCI_CONNECT_SECURE_COOKIE")
	if err != nil {
		return err
	}
	tlsCertificate := strings.TrimSpace(os.Getenv("GOCI_CONNECT_TLS_CERT_FILE"))
	tlsKey := strings.TrimSpace(os.Getenv("GOCI_CONNECT_TLS_KEY_FILE"))
	if (tlsCertificate == "") != (tlsKey == "") {
		return errors.New("GOCI_CONNECT_TLS_CERT_FILE and GOCI_CONNECT_TLS_KEY_FILE must be set together")
	}
	secureCookie = secureCookie || tlsCertificate != ""
	address := strings.TrimSpace(os.Getenv("GOCI_CONNECT_ADDR"))
	if address == "" {
		address = "127.0.0.1:8080"
	}
	app := newApplication(manager, newSessionStore(defaultSessionTTL), secureCookie, logger)
	server := &http.Server{
		Addr:              address,
		Handler:           app.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errChannel := make(chan error, 1)
	go func() {
		logger.Printf("listening on %s with providers %s", address, strings.Join(manager.Names(), ","))
		if tlsCertificate != "" {
			errChannel <- server.ListenAndServeTLS(tlsCertificate, tlsKey)
			return
		}
		errChannel <- server.ListenAndServe()
	}()

	select {
	case err := <-errChannel:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shut down HTTP server: %w", err)
		}
		if err := <-errChannel; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func managerFromEnvironment(getenv func(string) string) (*gociconnect.Manager, error) {
	manager := gociconnect.NewManager()
	configured := 0
	githubValues, githubEnabled, err := providerEnvironment(getenv, "GITHUB")
	if err != nil {
		return nil, err
	}
	if githubEnabled {
		provider, err := githubprovider.New(githubprovider.Config{
			ClientID:     githubValues.clientID,
			ClientSecret: githubValues.clientSecret,
			RedirectURL:  githubValues.redirectURL,
		})
		if err != nil {
			return nil, fmt.Errorf("configure GitHub provider: %w", err)
		}
		if err := manager.Register(provider); err != nil {
			return nil, err
		}
		configured++
	}
	googleValues, googleEnabled, err := providerEnvironment(getenv, "GOOGLE")
	if err != nil {
		return nil, err
	}
	if googleEnabled {
		provider, err := googleprovider.New(googleprovider.Config{
			ClientID:     googleValues.clientID,
			ClientSecret: googleValues.clientSecret,
			RedirectURL:  googleValues.redirectURL,
		})
		if err != nil {
			return nil, fmt.Errorf("configure Google provider: %w", err)
		}
		if err := manager.Register(provider); err != nil {
			return nil, err
		}
		configured++
	}
	if configured == 0 {
		return nil, errors.New("configure at least one complete GITHUB or GOOGLE provider environment")
	}
	return manager, nil
}

type providerValues struct {
	clientID     string
	clientSecret string
	redirectURL  string
}

func providerEnvironment(getenv func(string) string, prefix string) (providerValues, bool, error) {
	values := providerValues{
		clientID:     strings.TrimSpace(getenv(prefix + "_CLIENT_ID")),
		clientSecret: strings.TrimSpace(getenv(prefix + "_CLIENT_SECRET")),
		redirectURL:  strings.TrimSpace(getenv(prefix + "_REDIRECT_URL")),
	}
	if values == (providerValues{}) {
		return values, false, nil
	}
	missing := make([]string, 0, 3)
	if values.clientID == "" {
		missing = append(missing, prefix+"_CLIENT_ID")
	}
	if values.clientSecret == "" {
		missing = append(missing, prefix+"_CLIENT_SECRET")
	}
	if values.redirectURL == "" {
		missing = append(missing, prefix+"_REDIRECT_URL")
	}
	if len(missing) != 0 {
		return providerValues{}, false, fmt.Errorf("incomplete %s provider environment; missing %s", prefix, strings.Join(missing, ", "))
	}
	return values, true, nil
}

func booleanEnvironment(getenv func(string) string, name string) (bool, error) {
	value := strings.TrimSpace(getenv(name))
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return parsed, nil
}
