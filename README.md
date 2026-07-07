# oauth2client

An importable OAuth2 client for Python projects. It handles the manual
first-time authorization in your browser over an **mkcert**-secured HTTPS
callback, stores the token, and refreshes it automatically from then on.

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

> Headless server? Skip mkcert entirely and use `oauth2 authorize --manual`
> (see below) — it needs no local browser, callback server, or certificates.

### 3. Install dependencies

```bash
uv sync
```

## Getting the initial token (manual, one time per provider)

1. Register an application with your provider and note the **client id** and
   **client secret**.
2. Add the redirect URI `https://localhost:8400/callback` to the app
   registration (adjust the port if you pass `--port`).
3. Run `oauth2 authorize`. Your browser opens the provider's consent page;
   after you approve, the token is captured and saved to `working/tokens/`.

After that one manual step, `getAccessToken()` (or `oauth2 refresh`) renews
the token automatically using the refresh token.

## Using it from another project

```python
from oauth2client import OAuth2Client

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

Any provider not covered by a preset works through a `ProviderConfig`:

```python
from oauth2client import OAuth2Client, ProviderConfig

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

## CLI commands

Every command accepts `--working-dir` (default: `./working`).

### `oauth2 authorize`

Run the manual first-time authorization in your browser.

```bash
# Google — access_type=offline is required or Google won't issue a refresh token
uv run oauth2 authorize --provider google \
    --client-id YOUR_ID --client-secret YOUR_SECRET \
    --scopes "openid email https://www.googleapis.com/auth/drive.readonly" \
    --name myGoogle \
    --extra-auth-param access_type=offline --extra-auth-param prompt=consent

# Microsoft — include offline_access in scopes to receive a refresh token
uv run oauth2 authorize --provider microsoft --tenant yourtenant.onmicrosoft.com \
    --client-id YOUR_ID --client-secret YOUR_SECRET \
    --scopes "offline_access User.Read" \
    --name myMicrosoft

# D2L Brightspace
uv run oauth2 authorize --provider brightspace \
    --client-id YOUR_ID --client-secret YOUR_SECRET \
    --scopes "core:*:*" \
    --name myBrightspace

# Any other OAuth2 provider
uv run oauth2 authorize --provider generic \
    --auth-url https://provider.example.com/oauth/authorize \
    --token-url https://provider.example.com/oauth/token \
    --client-id YOUR_ID --client-secret YOUR_SECRET \
    --scopes "some.scope" --name myProvider
```

Options: `--port` (callback port, default 8400), `--timeout` (seconds to wait
for the browser, default 300), `--no-browser` (print the URL instead of
opening a browser), `--manual` (headless mode, below),
`--extra-auth-param KEY=VALUE` (repeatable).

#### Headless servers: `oauth2 authorize --manual`

On a server with no browser (SSH session, container, CI box), add `--manual`
to any of the commands above:

```bash
uv run oauth2 authorize --manual --provider google \
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

### `oauth2 refresh`

Refresh a saved token using the credentials stored with it.

```bash
uv run oauth2 refresh --name myGoogle
```

### `oauth2 status`

Show a saved token's provider, scopes, refresh-token presence, and expiry.

```bash
uv run oauth2 status --name myGoogle
```

### `oauth2 list`

List all saved tokens.

```bash
uv run oauth2 list
```

### `oauth2 delete`

Delete a saved token.

```bash
uv run oauth2 delete --name myGoogle
```

### `oauth2 providers`

List the supported provider presets.

```bash
uv run oauth2 providers
```

## Logging

All operations log informational events (INFO, ERROR) to
`working/logs/oauth2.log` and the console: authorization started, token
saved, token refreshed, provider errors, and so on.

## Security notes

- Token files under `working/tokens/` are saved owner-read-only (`0600`) and
  include the client id/secret so `oauth2 refresh` works without re-prompting.
  Keep `working/` out of version control (it is gitignored here).
- The callback server binds to `127.0.0.1` only and accepts a single
  authorization response; the `state` parameter is validated to block CSRF.

## Running tests

```bash
uv run pytest
```

Tests run against real local HTTP/HTTPS servers (no mocked behavior). The
mkcert tests are skipped automatically on machines without mkcert. See
[TESTPLAN.md](TESTPLAN.md) for the manual walkthrough.
