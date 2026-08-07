package main

import (
	"bytes"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	gociconnect "github.com/only1enes/goci-connect"
)

const sessionCookieName = "goci_connect_session"

type application struct {
	manager       *gociconnect.Manager
	sessions      *sessionStore
	secureCookies bool
	logger        *log.Logger
	indexTemplate *template.Template
	pageTemplate  *template.Template
}

type providerLink struct {
	Name string
	URL  string
}

type pageData struct {
	Title     string
	Message   string
	Provider  string
	Name      string
	Username  string
	Email     string
	Providers []providerLink
}

func newApplication(manager *gociconnect.Manager, sessions *sessionStore, secureCookies bool, logger *log.Logger) *application {
	if manager == nil {
		manager = gociconnect.NewManager()
	}
	if sessions == nil {
		sessions = newSessionStore(defaultSessionTTL)
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &application{
		manager:       manager,
		sessions:      sessions,
		secureCookies: secureCookies,
		logger:        logger,
		indexTemplate: template.Must(template.New("index").Parse(indexHTML)),
		pageTemplate:  template.Must(template.New("page").Parse(pageHTML)),
	}
}

func (app *application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", app.handleIndex)
	mux.HandleFunc("GET /auth/{provider}", app.handleBegin)
	mux.HandleFunc("GET /auth/{provider}/callback", app.handleCallback)
	return mux
}

func (app *application) handleIndex(writer http.ResponseWriter, _ *http.Request) {
	names := app.manager.Names()
	links := make([]providerLink, 0, len(names))
	for _, name := range names {
		links = append(links, providerLink{Name: name, URL: "/auth/" + url.PathEscape(name)})
	}
	app.render(writer, http.StatusOK, app.indexTemplate, pageData{
		Title:     "Goci Connect net/http example",
		Providers: links,
	})
}

func (app *application) handleBegin(writer http.ResponseWriter, request *http.Request) {
	providerName := request.PathValue("provider")
	provider, err := app.manager.Provider(providerName)
	if err != nil {
		app.renderError(writer, http.StatusNotFound, "Unknown authentication provider.")
		return
	}
	authorization, err := provider.Begin(request.Context(), gociconnect.BeginRequest{})
	if err != nil {
		app.logFailure("begin", providerName, err)
		app.renderError(writer, http.StatusBadGateway, "Authentication could not be started.")
		return
	}
	sessionID, expiresAt, err := app.sessions.create(providerName, authorization.Session)
	if err != nil {
		app.logger.Printf("authentication session creation failed provider=%q", providerName)
		app.renderError(writer, http.StatusInternalServerError, "Authentication could not be started.")
		return
	}
	http.SetCookie(writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/auth/",
		Expires:  expiresAt,
		MaxAge:   max(1, int(app.sessions.ttl/time.Second)),
		HttpOnly: true,
		Secure:   app.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
	setSecurityHeaders(writer)
	http.Redirect(writer, request, authorization.URL, http.StatusFound)
}

func (app *application) handleCallback(writer http.ResponseWriter, request *http.Request) {
	providerName := request.PathValue("provider")
	provider, err := app.manager.Provider(providerName)
	if err != nil {
		app.renderError(writer, http.StatusNotFound, "Unknown authentication provider.")
		return
	}
	cookie, err := request.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		app.renderError(writer, http.StatusBadRequest, "The authentication session is missing.")
		return
	}
	app.clearSessionCookie(writer)
	session, err := app.sessions.consume(cookie.Value, providerName)
	if err != nil {
		message := "The authentication session is invalid or has already been used."
		if errors.Is(err, errSessionExpired) {
			message = "The authentication session has expired."
		}
		app.renderError(writer, http.StatusBadRequest, message)
		return
	}
	user, err := provider.Complete(request.Context(), gociconnect.CompleteRequest{
		Callback: gociconnect.CallbackFromValues(request.URL.Query()),
		Session:  session,
	})
	if err != nil {
		app.logFailure("complete", providerName, err)
		switch {
		case errors.Is(err, gociconnect.ErrAuthorizationDenied):
			app.renderError(writer, http.StatusForbidden, "Authorization was declined.")
		case errors.Is(err, gociconnect.ErrInvalidRequest), errors.Is(err, gociconnect.ErrStateValidation):
			app.renderError(writer, http.StatusBadRequest, "The authentication callback was invalid.")
		default:
			app.renderError(writer, http.StatusBadGateway, "Authentication could not be completed.")
		}
		return
	}
	app.render(writer, http.StatusOK, app.pageTemplate, pageData{
		Title:    "Authentication complete",
		Message:  "The provider identity was loaded successfully.",
		Provider: user.Provider,
		Name:     user.Name,
		Username: user.Nickname,
		Email:    user.Email,
	})
}

func (app *application) clearSessionCookie(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/auth/",
		Expires:  time.Unix(1, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   app.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (app *application) renderError(writer http.ResponseWriter, status int, message string) {
	app.render(writer, status, app.pageTemplate, pageData{Title: "Authentication error", Message: message})
}

func (app *application) render(writer http.ResponseWriter, status int, page *template.Template, data pageData) {
	var body bytes.Buffer
	if err := page.Execute(&body, data); err != nil {
		app.logger.Print("HTML rendering failed")
		http.Error(writer, "Internal server error.", http.StatusInternalServerError)
		return
	}
	setSecurityHeaders(writer)
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = writer.Write(body.Bytes())
}

func (app *application) logFailure(operation, provider string, err error) {
	code, ok := gociconnect.ErrorCodeOf(err)
	if !ok {
		code = gociconnect.ErrorCodeUnknown
	}
	app.logger.Printf("authentication %s failed provider=%q category=%q", operation, provider, code)
}

func setSecurityHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
}

const indexHTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{{.Title}}</title>
<style>body{font:16px system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem;color:#202124}ul{padding:0;list-style:none}li{margin:.75rem 0}a{color:#0969da}code{font-family:ui-monospace,monospace}</style></head>
<body><main><h1>{{.Title}}</h1>{{if .Providers}}<p>Choose a configured provider:</p><ul>{{range .Providers}}<li><a href="{{.URL}}">Continue with {{.Name}}</a></li>{{end}}</ul>{{else}}<p>No providers are configured.</p>{{end}}</main></body>
</html>`

const pageHTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{{.Title}}</title>
<style>body{font:16px system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem;color:#202124}dt{font-weight:600;margin-top:.75rem}dd{margin:.2rem 0}a{color:#0969da}</style></head>
<body><main><h1>{{.Title}}</h1><p>{{.Message}}</p>{{if .Provider}}<dl><dt>Provider</dt><dd>{{.Provider}}</dd>{{if .Name}}<dt>Name</dt><dd>{{.Name}}</dd>{{end}}{{if .Username}}<dt>Username</dt><dd>{{.Username}}</dd>{{end}}{{if .Email}}<dt>Email</dt><dd>{{.Email}}</dd>{{end}}</dl>{{end}}<p><a href="/">Back to providers</a></p></main></body>
</html>`
