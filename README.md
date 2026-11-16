# simpleoauth2token

An importable OAuth2 client for Python projects. It handles the manual
first-time authorization in your browser over an **mkcert**-secured HTTPS
callback, stores the token, and refreshes it automatically from then on.
For service-to-service calls where no human signs in, it also supports the
client credentials grant (see
[Client credentials](#client-credentials-service-to-service-no-user)).

Works with **Google**, **Microsoft**, **D2L Brightspace**, and any standard
OAuth2 provider via the `generic` preset.

Everything generated at runtime — tokens, TLS certificates, and logs — lives
in a `working/` directory at the root of whatever project uses the library.

## Setup

### 1. Install uv

We use [uv](https://docs.astral.sh/uv/) for package and script management.

```bash
# macOS (Homebrew)
brew install uv

# or the official installer
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Install mkcert

The OAuth2 callback listens on `https://localhost`, so a locally-trusted TLS
certificate is required. [mkcert](https://github.com/FiloSottile/mkcert)
provides one:

```bash
brew install mkcert
mkcert -install   # one-time: trusts the local CA in your system/browser
```

Certificates are generated automatically into `working/certs/` the first time
you authorize.

> Headless server? Skip mkcert entirely and use `simpleoauth2token authorize --manual`
> (see below) — it needs no local browser, callback server, or certificates.

### 3. Install dependencies

```bash
uv sync
```

## Getting the initial token (manual, one time per provider)

1. Register an application with your provider and note the **client id** and
   **client secret**.
2. Add the redirect URI `https://localhost:8400/callback` to the app
   registration (adjust the port if you pass `--port`). If the registration
   already uses a different redirect URI, pass it with `--redirect-uri`.
3. Run `simpleoauth2token authorize`. Your browser opens the provider's consent page;
   after you approve, the token is captured and saved to `working/tokens/`.

After that one manual step, `getAccessToken()` (or `simpleoauth2token refresh`) renews
the token automatically using the refresh token.

## Using it from another project

### Installing as a dependency

Install from [PyPI](https://pypi.org/project/simpleoauth2token/):

```bash
uv add simpleoauth2token
```

To work against a local checkout instead (changes in this repo become
visible to the consuming project immediately), use a path dependency:

```bash
uv add --editable /path/to/simpleoauth2token
```

or install straight from the repository:
`uv add git+https://github.com/GSU-CETLOE/simpleoauth2token`.

> **Note:** the project was deliberately named `simpleoauth2token` (not
> `oauth2client`) to avoid colliding with Google's long-deprecated
> `oauth2client` package on PyPI.

The consuming project needs Python 3.13+ (`requires-python` here is
`>=3.13`). Each consuming project gets its own `working/` directory —
tokens do not follow the library, so authorize once per project or pass a
shared `workingDir`.

### Example

```python
from simpleoauth2token import OAuth2Client

client = OAuth2Client(
    provider="google",              # or "microsoft", "brightspace", or a ProviderConfig
    clientId="your-client-id",
    clientSecret="your-client-secret",
    scopes="openid email",
    tokenName="myGoogle",           # file name under working/tokens/
)

client.authorize()                  # first time only — opens the browser
accessToken = client.getAccessToken()  # every time after — auto-refreshes
```

If an API rejects a token that has not expired yet (for example the provider
revoked it early), renew it explicitly:

```python
accessToken = client.getAccessToken(forceRefresh=True)
```

Any provider not covered by a preset works through a `ProviderConfig`:

```python
from simpleoauth2token import OAuth2Client, ProviderConfig

client = OAuth2Client(
    provider=ProviderConfig(
        name="gitlab",
        authorizationUrl="https://gitlab.example.com/oauth/authorize",
        tokenUrl="https://gitlab.example.com/oauth/token",
    ),
    clientId="...",
    clientSecret="...",
    scopes="read_api",
    tokenName="myGitlab",
)
```

## Client credentials (service-to-service, no user)

When your code calls an API as _itself_ — a nightly sync job, a reporting
service — no human is there to click a consent page. The client credentials
grant exchanges the client's credential directly for an access token: no
browser, no callback server, no mkcert, and no manual first step. The
provider issues no refresh token; renewing simply re-runs the grant, which
`getAccessToken()` and `simpleoauth2token refresh` do automatically.

The client authenticates with its **secret** (Microsoft, generic providers)
or, where the provider requires it, with a **JWT client assertion** signed by
a private key (RFC 7523 — how **D2L Brightspace** service users work). Google
service accounts use a different JWT-bearer flow that this library does not
implement.

### Microsoft

Requirements from the Azure app registration:

- The token request must go to **your tenant's** endpoint — pass
  `tenant=...`; the default `common` endpoint rejects client credentials.
- The app needs **application permissions** (not delegated) with admin
  consent granted.
- The scope must be the resource's `.default` scope, e.g.
  `https://graph.microsoft.com/.default`.

```python
from simpleoauth2token import OAuth2Client

client = OAuth2Client(
    provider="microsoft",
    tenant="yourtenant.onmicrosoft.com",
    clientId="your-client-id",
    clientSecret="your-client-secret",
    scopes="https://graph.microsoft.com/.default",
    tokenName="graphService",
    grantType="client_credentials",
)
accessToken = client.getAccessToken()   # fetches and renews automatically
```

```bash
uv run simpleoauth2token authorize --client-credentials \
    --provider microsoft --tenant yourtenant.onmicrosoft.com \
    --client-id YOUR_ID --client-secret YOUR_SECRET \
    --scopes "https://graph.microsoft.com/.default" \
    --name graphService
```

### D2L Brightspace (JWT client assertions + service users)

Brightspace client-credentials applications have **no client secret**: every
token request authenticates with a short-lived JWT signed by your private
key, which Brightspace validates against a public **JWKS** hosted at an HTTPS
URL you register. Setup, following
[D2L's service-user documentation](https://community.d2l.com/brightspace/kb/articles/34318-service-users-and-server-to-server-authentication-for-brightspace):

1. Generate a signing key and its JWKS:

   ```bash
   uv run simpleoauth2token keygen --kid myServiceKey
   ```

   This writes `working/keys/myServiceKey.pem` (private, keep it secret) and
   `working/keys/myServiceKey.jwks.json` (public).

2. Host the JWKS JSON at an HTTPS URL (any static hosting works).
3. In Brightspace (Manage Extensibility > OAuth 2.0), create a **service
   user**, register an application with the **Client Credentials** grant,
   give it the JWKS URL, and link the service user to it.
4. Authorize with the key instead of a secret:

```python
from simpleoauth2token import OAuth2Client

client = OAuth2Client(
    provider="brightspace",
    clientId="your-client-id",
    scopes="core:*:*",
    tokenName="brightspaceService",
    grantType="client_credentials",
    privateKeyFile="working/keys/myServiceKey.pem",
    keyId="myServiceKey",
)
accessToken = client.getAccessToken()   # fetches and renews automatically
```

```bash
uv run simpleoauth2token authorize --client-credentials --provider brightspace \
    --client-id YOUR_ID \
    --private-key working/keys/myServiceKey.pem --kid myServiceKey \
    --scopes "core:*:*" \
    --name brightspaceService
```

Each assertion lives 60 seconds and carries a unique `jti`, per Brightspace's
requirements; keys are ES256 (P-256) by default, and `--assertion-algorithm`
selects another RSA/EC algorithm if you generated a different key type. API
calls then run with the permissions of the linked service user.

Any other provider that supports the grant works through `generic` —
`--auth-url` is not needed because no authorization endpoint is ever visited:

```bash
uv run simpleoauth2token authorize --client-credentials --provider generic \
    --token-url https://provider.example.com/oauth/token \
    --client-id YOUR_ID --client-secret YOUR_SECRET \
    --scopes "some.scope" --name myService
```

## CLI commands

Every command accepts `--working-dir` (default: `./working`).

### `simpleoauth2token authorize`

Run the manual first-time authorization in your browser.

```bash
# Google — access_type=offline is required or Google won't issue a refresh token
uv run simpleoauth2token authorize --provider google \
    --client-id YOUR_ID --client-secret YOUR_SECRET \
    --scopes "openid email https://www.googleapis.com/auth/drive.readonly" \
    --name myGoogle \
    --extra-auth-param access_type=offline --extra-auth-param prompt=consent

# Microsoft — include offline_access in scopes to receive a refresh token
uv run simpleoauth2token authorize --provider microsoft --tenant yourtenant.onmicrosoft.com \
    --client-id YOUR_ID --client-secret YOUR_SECRET \
    --scopes "offline_access User.Read" \
    --name myMicrosoft

# D2L Brightspace
uv run simpleoauth2token authorize --provider brightspace \
    --client-id YOUR_ID --client-secret YOUR_SECRET \
    --scopes "core:*:*" \
    --name myBrightspace

# Any other OAuth2 provider
uv run simpleoauth2token authorize --provider generic \
    --auth-url https://provider.example.com/oauth/authorize \
    --token-url https://provider.example.com/oauth/token \
    --client-id YOUR_ID --client-secret YOUR_SECRET \
    --scopes "some.scope" --name myProvider
```

Options: `--port` (callback port, default 8400), `--redirect-uri` (the
redirect URI exactly as registered with the provider, when it is not
`https://localhost:<port>/callback`; overrides `--port`, and a host other than
localhost only works with `--manual`), `--timeout` (seconds to wait
for the browser, default 300), `--no-browser` (print the URL instead of
opening a browser), `--manual` (headless mode, below),
`--client-credentials` (service-to-service grant, no user — see
[Client credentials](#client-credentials-service-to-service-no-user)),
`--private-key PEM --kid KEYID` (authenticate with a JWT client assertion
instead of `--client-secret`; Brightspace service users),
`--assertion-algorithm` (default ES256),
`--extra-auth-param KEY=VALUE` (repeatable).

#### Headless servers: `simpleoauth2token authorize --manual`

On a server with no browser (SSH session, container, CI box), add `--manual`
to any of the commands above:

```bash
uv run simpleoauth2token authorize --manual --provider google \
    --client-id YOUR_ID --client-secret YOUR_SECRET \
    --scopes "openid email" --name myGoogle \
    --extra-auth-param access_type=offline --extra-auth-param prompt=consent
```

1. The CLI prints the authorization URL. Open it in a browser on **any**
   device (your laptop, your phone) and approve access.
2. The browser is redirected to `https://localhost:8400/callback` and shows a
   connection error — that is expected, since nothing is listening. The
   authorization code is in the address bar.
3. Copy the full URL from the address bar and paste it into the waiting CLI
   prompt (a bare code also works). The token is exchanged and saved exactly
   as in the browser flow.

Manual mode needs no local browser, no callback server, and no mkcert. From a
library, the same flow is `client.authorizeManual()`.

### `simpleoauth2token refresh`

Refresh a saved token using the credentials stored with it. Tokens obtained
with `--client-credentials` are renewed by re-running that grant.

If a refresh that used to work starts failing with `invalid_client`, the
client secret has likely been rotated or expired (Azure secrets always
expire) — the error says so, and the fix is re-running `simpleoauth2token authorize`
with current credentials. For assertion-authenticated tokens the same error
means the provider could no longer validate the signature — check that the
registered JWKS is still hosted and contains the key.

```bash
uv run simpleoauth2token refresh --name myGoogle
```

### `simpleoauth2token status`

Show a saved token's provider, grant, scopes, refresh-token presence, and
expiry.

```bash
uv run simpleoauth2token status --name myGoogle
```

### `simpleoauth2token list`

List all saved tokens.

```bash
uv run simpleoauth2token list
```

### `simpleoauth2token delete`

Delete a saved token.

```bash
uv run simpleoauth2token delete --name myGoogle
```

### `simpleoauth2token providers`

List the supported provider presets.

```bash
uv run simpleoauth2token providers
```

### `simpleoauth2token keygen`

Generate a signing keypair for providers that authenticate with JWT client
assertions (Brightspace service users). Writes the private key
(owner-read-only) and the public JWKS into `working/keys/`, prints the JWKS,
and refuses to overwrite an existing key — regenerating a registered key
would break every deployment still signing with it.

```bash
uv run simpleoauth2token keygen --kid myServiceKey
uv run simpleoauth2token keygen --kid myRsaKey --algorithm RS256
```

Options: `--algorithm` (ES256 default, or ES384/ES512/RS256/RS384/RS512),
`--out` (output directory, default `<working-dir>/keys`). Host the printed
JWKS at an HTTPS URL and register that URL with your provider.

## Logging

All operations log informational events (INFO, ERROR) to
`working/logs/oauth2.log` and the console: authorization started, token
saved, token refreshed, provider errors, and so on.

## Security notes

- Token files under `working/tokens/` are saved owner-read-only (`0600`) and
  include the client id/secret so `simpleoauth2token refresh` works without re-prompting.
  Keep `working/` out of version control (it is gitignored here).
- For JWT-assertion clients the token file stores only the private key's
  *path*, key id, and algorithm — never the key material. `keygen` writes
  private keys owner-read-only (`0600`) into `working/keys/`; the JWKS it
  emits contains only the public key and is safe to host.
- Token writes are atomic (owner-only temp file renamed into place), so
  concurrent processes sharing a working directory never read a partial
  token and the secrets are never on disk with wider permissions.
- The callback server binds to `127.0.0.1` only and accepts a single
  authorization response; the `state` parameter is validated to block CSRF.

## Running tests

```bash
uv run pytest
```

Tests run against real local HTTP/HTTPS servers (no mocked behavior). The
mkcert tests are skipped automatically on machines without mkcert. See
[TESTPLAN.md](TESTPLAN.md) for the manual walkthrough.

## License

[MIT](LICENSE)
