# net/http example

This example shows a complete authorization-code login flow using Goci Connect
and only the Go standard library's `net/http` server.

Configure at least one provider with a complete set of variables:

| Provider | Required variables                                                |
| -------- | ----------------------------------------------------------------- |
| GitHub   | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_REDIRECT_URL` |
| Google   | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URL` |

From the repository root, copy the committed template and fill in credentials
for GitHub, Google, or both:

```powershell
Copy-Item .env.example .env
```

The example loads `.env` at startup. Existing process environment variables
take precedence over values in the file. The populated `.env` is ignored by
Git and must never be committed.

For the default local address, use these callback URLs in the corresponding
provider application settings:

```text
http://127.0.0.1:8080/auth/github/callback
http://127.0.0.1:8080/auth/google/callback
```

Each configured `*_REDIRECT_URL` must exactly match its registered callback.
The application works with either provider by itself or with both providers.

Run it from the repository root:

```sh
go run ./examples/nethttp
```

Then open `http://127.0.0.1:8080/`.

Optional environment variables:

| Variable                     | Purpose                                                 |
| ---------------------------- | ------------------------------------------------------- |
| `GOCI_CONNECT_ADDR`          | Listen address; defaults to `127.0.0.1:8080`.           |
| `GOCI_CONNECT_TLS_CERT_FILE` | TLS certificate file used by `ListenAndServeTLS`.       |
| `GOCI_CONNECT_TLS_KEY_FILE`  | TLS private-key file used by `ListenAndServeTLS`.       |
| `GOCI_CONNECT_SECURE_COOKIE` | Set to `true` when HTTPS terminates at a reverse proxy. |

Direct TLS requires both TLS file variables. Direct TLS and the secure-cookie
option both set the authorization cookie's `Secure` attribute.

The browser cookie contains only a cryptographically random opaque identifier.
Authorization state and the PKCE verifier stay in a server-side in-memory map,
expire after ten minutes, and are consumed once at callback time. Tokens are
never rendered by the example.

The in-memory store is intentionally suitable only for this local example. It
is lost on restart, is not shared between processes, and is not production-ready
distributed session storage.
