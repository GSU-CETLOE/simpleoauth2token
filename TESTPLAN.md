# Test Plan

Keep this document current: when a command or behavior is added or changed,
update the matching checklist here.

## Automated suite

- [ ] `uv run pytest` — all tests pass, output pristine (no warnings/errors)
  - Covers: provider presets, token store persistence and permissions,
    logging service, HTTPS callback server (real TLS via trustme), client
    token exchange/refresh against a real local endpoint, the client
    credentials grant (fetch, auto-renewal, CLI), JWT client assertions
    (signing-key generation, JWKS output, assertion claims, signature
    verification by the fake endpoint, key-path renewal), mkcert
    certificate generation, and the non-interactive CLI commands.

## CLI walkthrough

Prerequisites: `uv sync` done; mkcert installed and `mkcert -install` run.

### simpleoauth2token providers

- [ ] `uv run simpleoauth2token providers` prints `brightspace`, `generic`, `google`,
      `microsoft` and exits 0.

### simpleoauth2token authorize

- [ ] `uv run simpleoauth2token authorize` with no flags exits non-zero and shows usage.
- [ ] Real provider run (use any one provider you have credentials for):
      `uv run simpleoauth2token authorize --provider google --client-id ... --client-secret ... --scopes "openid email" --name testToken --extra-auth-param access_type=offline --extra-auth-param prompt=consent`
  - [ ] First run generates `working/certs/localhost.pem` and logs the event.
  - [ ] Browser opens the provider consent page automatically.
  - [ ] After approving, the browser shows "Authorization complete".
  - [ ] CLI prints `Token 'testToken' saved.` with an expiry and exits 0.
  - [ ] `working/tokens/testToken.json` exists with permissions `-rw-------`.
  - [ ] `working/logs/oauth2.log` contains the INFO events for the run.
- [ ] `--no-browser` prints the authorization URL instead of opening a browser.
- [ ] Denying consent at the provider makes the CLI exit 1 with the
      provider's error (e.g. `access_denied`) printed and logged as ERROR.
- [ ] `--timeout 5` with no browser action exits 1 with a timeout error.
- [ ] `--provider generic` without `--auth-url`/`--token-url` exits 1 with a
      clear error.
- [ ] `--provider microsoft --tenant <tenant>` sends you to that tenant's
      login page.

- [ ] `--redirect-uri https://localhost:8400/some/other/path` (registered
      with the provider) completes the browser flow and saves the token.
- [ ] `--redirect-uri https://example.com/callback` without `--manual` exits 1
      and says to use `--manual`.

### simpleoauth2token authorize --manual (headless)

Run these over SSH or in a terminal, treating it as a machine with no browser.

- [ ] `uv run simpleoauth2token authorize --manual --provider <provider> ...` prints the
      authorization URL and instructions, then waits at a paste prompt —
      without opening a browser and without generating `working/certs/`.
- [ ] Opening the URL on another device and approving lands the browser on
      `https://localhost:8400/callback` with a connection error; the address
      bar contains `code=` and `state=`.
- [ ] Pasting that full URL at the prompt prints `Token '<name>' saved.`
      with an expiry and exits 0; the token appears in `working/tokens/`.
- [ ] Pasting a URL whose `state` was tampered with exits 1 with a state
      mismatch error and saves nothing.
- [ ] Pasting an empty line exits 1 with an error saying nothing was entered.
- [ ] Works with mkcert not installed on the machine.

### simpleoauth2token authorize --client-credentials (service-to-service, no user)

Use a Microsoft or Brightspace app registration set up for the client
credentials grant (Google is not supported for this grant).

- [ ] `uv run simpleoauth2token authorize --client-credentials --provider microsoft --tenant <tenant> --client-id ... --client-secret ... --scopes "https://graph.microsoft.com/.default" --name serviceToken`
      prints `Token 'serviceToken' saved.` with an expiry and exits 0 —
      without opening a browser and without generating `working/certs/`.
- [ ] `uv run simpleoauth2token status --name serviceToken` shows
      `Grant: client_credentials` and `Refresh token: absent`.
- [ ] `uv run simpleoauth2token refresh --name serviceToken` renews the token by
      re-running the grant and exits 0.
- [ ] A wrong client secret exits 1 with the provider's error printed and
      logged as ERROR.
- [ ] `--provider generic` works with only `--token-url` (no `--auth-url`
      required).
- [ ] `--client-secret` omitted (and no `--private-key`) exits 1 with an
      error naming both options.

### simpleoauth2token keygen + authorize --private-key (JWT client assertions)

Brightspace service users authenticate with JWT client assertions instead of
a client secret; see the README's Brightspace section for the registration
steps.

- [ ] `uv run simpleoauth2token keygen --kid myServiceKey` writes
      `working/keys/myServiceKey.pem` with permissions `-rw-------` and
      `working/keys/myServiceKey.jwks.json`, prints the JWKS with hosting
      instructions, and exits 0.
- [ ] Running the same command again exits 1 with an "already exists" error
      and leaves the original key untouched.
- [ ] `--algorithm RS256` produces an RSA key (`"kty": "RSA"` in the JWKS).
- [ ] With the JWKS hosted and registered to a Brightspace client-credentials
      app linked to a service user:
      `uv run simpleoauth2token authorize --client-credentials --provider brightspace --client-id ... --private-key working/keys/myServiceKey.pem --kid myServiceKey --scopes "..." --name brightspaceService`
      prints `Token 'brightspaceService' saved.` and exits 0 — no
      `--client-secret` anywhere.
- [ ] `uv run simpleoauth2token status --name brightspaceService` shows the
      `Signing key:` line with the key path and kid.
- [ ] `uv run simpleoauth2token refresh --name brightspaceService` renews by
      re-signing a fresh assertion from the stored key path; exits 0.
- [ ] `--private-key` without `--kid` exits 1 with an error naming `--kid`.
- [ ] `--private-key` without `--client-credentials` exits 1 with an error
      naming `--client-credentials`.
- [ ] Signing with a key whose JWKS is *not* registered exits 1 with
      `invalid_client` plus the JWKS hint.

### simpleoauth2token status

- [ ] `uv run simpleoauth2token status --name testToken` shows provider, scopes,
      `Refresh token: present`, and `valid until <timestamp>`; exits 0.
- [ ] After the access token expires, status shows `expired at <timestamp>`.
- [ ] `uv run simpleoauth2token status --name doesNotExist` exits 1 with an error on
      stderr.

### simpleoauth2token refresh

- [ ] `uv run simpleoauth2token refresh --name testToken` prints
      `Token 'testToken' refreshed.` with a new expiry and exits 0.
- [ ] `working/logs/oauth2.log` gains a `token 'testToken' refreshed` INFO event.
- [ ] `uv run simpleoauth2token refresh --name doesNotExist` exits 1 with an error.
- [ ] After rotating the client secret at the provider, refresh exits 1 with
      `invalid_client` plus the hint that the secret may have been rotated
      or expired.

### simpleoauth2token list

- [ ] `uv run simpleoauth2token list` shows `testToken`; exits 0.
- [ ] With an empty working dir (`--working-dir /tmp/emptydir`), prints
      `No tokens saved yet.` and exits 0.

### simpleoauth2token delete

- [ ] `uv run simpleoauth2token delete --name testToken` prints
      `Token 'testToken' deleted.` and removes the file; exits 0.
- [ ] Running it again exits 1 with an error on stderr.

## Library usage

- [ ] In a separate project, `from simpleoauth2token import OAuth2Client` works
      and `getAccessToken()` returns the saved token without a browser.
- [ ] With an expired access token and valid refresh token,
      `getAccessToken()` refreshes transparently and returns a new token.
- [ ] With no saved token, `getAccessToken()` raises `OAuth2Error` telling
      you to run authorize.
- [ ] With `grantType="client_credentials"` and no saved token,
      `getAccessToken()` obtains a token on its own — no manual step, no
      browser — and renews it after expiry the same way.
- [ ] Same with `privateKeyFile=...` and `keyId=...` in place of
      `clientSecret` (JWT client assertion): `getAccessToken()` fetches and
      renews with no manual step.
- [ ] `getAccessToken(forceRefresh=True)` renews a token that has not
      expired yet (use after an API answers 401 for a revoked token).
